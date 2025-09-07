// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Importações do OpenZeppelin para funcionalidades padrão e segurança
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ArenaCoin - Enhanced DeFi Token with Advanced Features
 * @dev Token DeFi completo com sistema de travamento de liquidez, governança com timelock e proteção anti-bot
 */
contract ArenaCoin is ERC20, ERC20Burnable, Ownable, ReentrancyGuard {
    
    // ============ CONSTANTES ============
    // Não podem ser alteradas após o deploy
    
    uint256 private constant MAX_SUPPLY = 12e9 * 1e18; // 12 bilhões de tokens (com 18 decimais)
    uint256 private constant INITIAL_TAX_PERIOD = 1 hours; // Período de taxa alta: 1 hora
    uint256 private constant MAX_TAX_RATE = 300; // Taxa máxima permitida: 3% (300 basis points)
    uint256 private constant TIMELOCK_DELAY = 24 hours; // Delay obrigatório para mudanças: 24 horas
    uint256 private constant MIN_TEMP_LOCK = 30 days; // Tempo mínimo para travamento temporário: 30 dias
    uint256 private constant MAX_TEMP_LOCK = 1825 days; // Tempo máximo para travamento: 5 anos

    // ============ VARIÁVEIS DE ESTADO ============
    // Podem ser alteradas durante a operação do contrato
    
    uint256 public launchTime; // Timestamp de quando o trading foi habilitado
    bool public tradingEnabled; // Se o trading público está ativo
    bool public paused; // Se o contrato está pausado

    // Sistema de taxas
    uint256 public initialTaxRate = 200; // Taxa inicial: 2% (200 basis points)
    uint256 public normalTaxRate = 50; // Taxa normal: 0.5% (50 basis points)
    address public taxRecipient; // Endereço que recebe as taxas
    bool public taxEnabled = true; // Se as taxas estão ativas

    // Mapeamentos para controle de acesso
    mapping(address => bool) public isExcludedFromTax; // Endereços isentos de taxa
    mapping(address => bool) public isExcludedFromLimits; // Endereços isentos de limites
    mapping(address => bool) public isAMM; // Endereços marcados como AMM (exchanges)

    // Estrutura para armazenar dados de travamento de liquidez
    struct LiquidityLock {
        uint256 amount; // Quantidade de tokens travados
        uint256 unlockTime; // Timestamp para destravar (0 se permanente)
        address lpToken; // Endereço do token LP travado
        address locker; // Quem fez o travamento
        bool isActive; // Se o travamento está ativo
        bool isPermanent; // Se é um travamento permanente
    }

    // Estrutura para mudanças pendentes (sistema timelock)
    struct PendingChange {
        uint256 executeTime; // Quando pode ser executada
        uint256 param1; // Primeiro parâmetro
        uint256 param2; // Segundo parâmetro
        address addr; // Endereço (se aplicável)
        bool exists; // Se a mudança existe
        address scheduledBy; // Quem agendou a mudança
    }

    // Mapeamentos para rastreamento de travamentos
    mapping(uint256 => LiquidityLock) public liquidityLocks; // ID do lock => dados do lock
    mapping(address => uint256[]) public userLocks; // usuário => array de IDs dos seus locks
    mapping(bytes32 => PendingChange) public pendingChanges; // ID da mudança => dados da mudança
    mapping(address => uint256) public lpTokenTotalLocked; // token LP => quantidade total travada

    // Variáveis de controle
    uint256 public nextLockId = 1; // Próximo ID de lock disponível
    uint256 public totalLockedValue; // Valor total travado
    uint256 public totalPermanentLocks; // Número total de locks permanentes
    uint256 private _nonce; // Nonce para gerar IDs únicos

    // ============ EVENTOS ============
    // Logs de ações importantes para transparência
    
    event TradingEnabled(uint256 timestamp, address enabledBy); // Trading foi habilitado
    event TaxRatesUpdated(uint256 initialRate, uint256 normalRate, address updatedBy); // Taxas alteradas
    event TaxRecipientUpdated(address oldRecipient, address newRecipient, address updatedBy); // Destinatário da taxa alterado
    event LiquidityLocked(uint256 lockId, address locker, address lpToken, uint256 amount, bool permanent, uint256 unlockTime); // Liquidez travada
    event LiquidityUnlocked(uint256 lockId, address user, uint256 amount); // Liquidez destravada
    event LiquidityMadePermanent(uint256 lockId, address locker); // Lock tornado permanente
    event ChangeScheduled(bytes32 changeId, string changeType, uint256 executeTime, address scheduledBy); // Mudança agendada
    event ChangeExecuted(bytes32 changeId, string changeType, address executedBy); // Mudança executada
    event ChangeCancelled(bytes32 changeId, address cancelledBy); // Mudança cancelada
    event PausedStateChanged(bool paused, address changedBy); // Estado de pausa alterado
    event TaxToggled(bool enabled, address changedBy); // Sistema de taxa ligado/desligado
    event ExclusionsUpdated(address account, bool excludeFromTax, bool excludeFromLimits, address updatedBy); // Exclusões atualizadas
    event AMMUpdated(address amm, bool status, address updatedBy); // Status de AMM atualizado
    event EmergencyRecovery(address token, address to, uint256 amount, address recoveredBy); // Recuperação de emergência

    // ============ MODIFICADORES ============
    // Verificações reutilizáveis para funções
    
    // Permite execução apenas quando o contrato não está pausado
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    // Verifica se o ID do lock é válido e está ativo
    modifier validLockId(uint256 lockId) {
        require(lockId > 0 && lockId < nextLockId, "Invalid lock ID");
        require(liquidityLocks[lockId].isActive, "Lock not active");
        _;
    }

    // Verifica se o endereço não é zero
    modifier validAddress(address addr) {
        require(addr != address(0), "Zero address not allowed");
        _;
    }

    // ============ CONSTRUCTOR ============
    // Executado apenas uma vez no deploy
    
    constructor(address _taxRecipient) 
        ERC20("ArenaCoin", "ARENA") // Nome e símbolo do token
        Ownable(msg.sender) // Define o deployer como owner
    {
        // Valida se o destinatário da taxa não é endereço zero
        require(_taxRecipient != address(0), "Invalid tax recipient");
        
        // Define o destinatário das taxas
        taxRecipient = _taxRecipient;
        
        // Configura exclusões iniciais (deployer, destinatário da taxa e contrato)
        _setExclusions(msg.sender, true, true); // Deployer isento de tudo
        _setExclusions(_taxRecipient, true, true); // Destinatário da taxa isento
        _setExclusions(address(this), true, true); // Contrato isento

        // Cria todo o supply inicial para o deployer
        _mint(msg.sender, MAX_SUPPLY);
    }

    // ============ LÓGICA PRINCIPAL DE TRANSFERÊNCIA ============
    // Função interna chamada em todas as transferências
    
    function _update(address from, address to, uint256 amount) internal override whenNotPaused {
        // Pula verificações para mint (from = 0) e burn (to = 0)
        if (from != address(0) && to != address(0)) {
            
            // Verificação de restrição de trading
            if (!tradingEnabled) {
                require(
                    from == owner() || // Owner sempre pode transferir
                    isExcludedFromLimits[from] || // Remetente isento
                    isExcludedFromLimits[to], // Destinatário isento
                    "Trading not enabled"
                );
            }

            // NOTA: Sem limite máximo de carteira - usuários podem comprar qualquer quantidade
        }

        // Calcula e aplica taxa
        uint256 taxAmount = _calculateTax(from, to, amount);
        if (taxAmount > 0) {
            // Se há taxa, faz duas transferências: taxa para o destinatário e resto para o usuário
            super._update(from, taxRecipient, taxAmount);
            super._update(from, to, amount - taxAmount);
            return;
        }

        // Se não há taxa, transferência normal
        super._update(from, to, amount);
    }

    // Calcula a taxa a ser aplicada na transferência
    function _calculateTax(address from, address to, uint256 amount) private view returns (uint256) {
        // Sem taxa para mint/burn ou se sistema desabilitado
        if (from == address(0) || to == address(0) || !taxEnabled) return 0;
        
        // Sem taxa se remetente ou destinatário está isento
        if (isExcludedFromTax[from] || isExcludedFromTax[to]) return 0;

        // Calcula taxa baseada na taxa atual
        uint256 currentRate = getCurrentTaxRate();
        return currentRate > 0 ? (amount * currentRate) / 10000 : 0; // Divide por 10000 para basis points
    }

    // Retorna a taxa atual (alta inicial, depois normal)
    function getCurrentTaxRate() public view returns (uint256) {
        if (!taxEnabled) return 0; // Se desabilitado, taxa zero
        if (launchTime == 0) return initialTaxRate; // Se ainda não lançou, taxa inicial
        
        // Se dentro do período inicial (1 hora), taxa alta; senão, taxa normal
        return block.timestamp < launchTime + INITIAL_TAX_PERIOD ? initialTaxRate : normalTaxRate;
    }

    // ============ SISTEMA DE TRAVAMENTO DE LIQUIDEZ ============
    // Permite travar tokens LP por tempo determinado ou permanentemente
    
    function lockLiquidity(
        address lpToken, // Endereço do token LP a ser travado
        uint256 amount, // Quantidade a travar
        uint256 duration, // Duração em segundos (ignorado se permanente)
        bool permanent // Se é travamento permanente
    ) external nonReentrant validAddress(lpToken) returns (uint256 lockId) {
        require(amount > 0, "Amount must be greater than 0");
        
        // Se não é permanente, valida duração
        if (!permanent) {
            require(
                duration >= MIN_TEMP_LOCK && duration <= MAX_TEMP_LOCK, 
                "Invalid lock duration"
            );
        }

        // Transfere tokens LP do usuário para o contrato
        IERC20(lpToken).transferFrom(msg.sender, address(this), amount);

        // Gera novo ID de lock
        lockId = nextLockId++;
        
        // Calcula timestamp de desbloqueio (0 se permanente)
        uint256 unlockTime = permanent ? 0 : block.timestamp + duration;

        // Cria registro do lock
        liquidityLocks[lockId] = LiquidityLock({
            amount: amount,
            unlockTime: unlockTime,
            lpToken: lpToken,
            locker: msg.sender,
            isActive: true,
            isPermanent: permanent
        });

        // Adiciona à lista de locks do usuário
        userLocks[msg.sender].push(lockId);
        
        // Atualiza contadores
        totalLockedValue += amount;
        if (permanent) totalPermanentLocks++;
        lpTokenTotalLocked[lpToken] += amount;

        // Emite evento
        emit LiquidityLocked(lockId, msg.sender, lpToken, amount, permanent, unlockTime);
    }

    // Destravar liquidez (apenas para locks temporários e expirados)
    function unlockLiquidity(uint256 lockId) external nonReentrant validLockId(lockId) {
        LiquidityLock storage lock = liquidityLocks[lockId];
        
        // Validações
        require(!lock.isPermanent, "Cannot unlock permanent lock");
        require(lock.unlockTime > 0, "Invalid unlock time");
        require(block.timestamp >= lock.unlockTime, "Lock not expired");
        require(lock.locker == msg.sender, "Not lock owner");
        
        uint256 amount = lock.amount;
        address lpToken = lock.lpToken;

        // Remove lock da lista do usuário
        _removeUserLock(msg.sender, lockId);
        
        // Desativa lock e atualiza contadores
        lock.isActive = false;
        totalLockedValue -= amount;
        lpTokenTotalLocked[lpToken] -= amount;

        // Transfere tokens de volta para o usuário
        IERC20(lpToken).transfer(msg.sender, amount);
        emit LiquidityUnlocked(lockId, msg.sender, amount);
    }

    // Tornar um lock temporário em permanente
    function makeLockPermanent(uint256 lockId) external validLockId(lockId) {
        LiquidityLock storage lock = liquidityLocks[lockId];
        require(!lock.isPermanent, "Already permanent");
        require(lock.locker == msg.sender, "Not lock owner");

        // Atualiza para permanente
        lock.isPermanent = true;
        lock.unlockTime = 0;
        totalPermanentLocks++;

        emit LiquidityMadePermanent(lockId, msg.sender);
    }

    // Remove lock da lista de locks do usuário (função auxiliar)
    function _removeUserLock(address user, uint256 lockId) private {
        uint256[] storage locks = userLocks[user];
        for (uint256 i = 0; i < locks.length; i++) {
            if (locks[i] == lockId) {
                // Move último elemento para posição atual e remove último
                locks[i] = locks[locks.length - 1];
                locks.pop();
                break;
            }
        }
    }

    // ============ SISTEMA DE GOVERNANÇA COM TIMELOCK ============
    // Mudanças importantes requerem 24h de espera
    
    // Agendar uma mudança (owner only)
    function scheduleChange(
        string memory changeType, // Tipo de mudança ("TAX_RATES", "TAX_RECIPIENT")
        uint256 param1, // Primeiro parâmetro
        uint256 param2, // Segundo parâmetro  
        address addr // Endereço (se aplicável)
    ) external onlyOwner returns (bytes32 changeId) {
        // Gera ID único para a mudança
        changeId = keccak256(abi.encodePacked(changeType, block.timestamp, msg.sender, _nonce++));
        
        // Cria registro da mudança pendente
        pendingChanges[changeId] = PendingChange({
            executeTime: block.timestamp + TIMELOCK_DELAY, // Pode executar em 24h
            param1: param1,
            param2: param2,
            addr: addr,
            exists: true,
            scheduledBy: msg.sender
        });

        emit ChangeScheduled(changeId, changeType, block.timestamp + TIMELOCK_DELAY, msg.sender);
    }

    // Executar mudança agendada (owner only)
    function executeChange(bytes32 changeId, string memory changeType) external onlyOwner {
        PendingChange memory change = pendingChanges[changeId];
        
        // Validações
        require(change.exists, "Change not found");
        require(block.timestamp >= change.executeTime, "Timelock not expired");
        require(block.timestamp <= change.executeTime + 7 days, "Change expired"); // Expira em 7 dias

        bytes32 typeHash = keccak256(bytes(changeType));

        // Executa baseado no tipo de mudança
        if (typeHash == keccak256(bytes("TAX_RATES"))) {
            // Mudança de taxas
            require(change.param1 <= MAX_TAX_RATE && change.param2 <= MAX_TAX_RATE, "Tax rate too high");
            initialTaxRate = change.param1;
            normalTaxRate = change.param2;
            emit TaxRatesUpdated(change.param1, change.param2, msg.sender);
            
        } else if (typeHash == keccak256(bytes("TAX_RECIPIENT"))) {
            // Mudança de destinatário da taxa
            require(change.addr != address(0), "Invalid recipient");
            address oldRecipient = taxRecipient;
            taxRecipient = change.addr;
            emit TaxRecipientUpdated(oldRecipient, change.addr, msg.sender);
            
        } else {
            revert("Invalid change type");
        }

        // Remove mudança da lista
        delete pendingChanges[changeId];
        emit ChangeExecuted(changeId, changeType, msg.sender);
    }

    // Cancelar mudança pendente (owner only)
    function cancelPendingChange(bytes32 changeId) external onlyOwner {
        require(pendingChanges[changeId].exists, "Change not found");
        delete pendingChanges[changeId];
        emit ChangeCancelled(changeId, msg.sender);
    }

    // ============ FUNÇÕES ADMINISTRATIVAS ============
    // Controles do owner para gerenciar o token
    
    // Habilitar trading (irreversível)
    function enableTrading() external onlyOwner {
        require(!tradingEnabled, "Trading already enabled");
        tradingEnabled = true;
        launchTime = block.timestamp; // Registra momento do lançamento
        emit TradingEnabled(block.timestamp, msg.sender);
    }

    // Pausar/despausar contrato
    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedStateChanged(_paused, msg.sender);
    }

    // Configurar exclusões de taxa e limites
    function setExclusions(
        address account, 
        bool excludeFromTax, // Se isento de taxa
        bool excludeFromLimits // Se isento de limites
    ) external onlyOwner validAddress(account) {
        _setExclusions(account, excludeFromTax, excludeFromLimits);
    }

    // Função auxiliar para configurar exclusões
    function _setExclusions(address account, bool excludeFromTax, bool excludeFromLimits) private {
        isExcludedFromTax[account] = excludeFromTax;
        isExcludedFromLimits[account] = excludeFromLimits;
        emit ExclusionsUpdated(account, excludeFromTax, excludeFromLimits, msg.sender);
    }

    // Marcar endereço como AMM (exchange)
    function setAMM(address amm, bool status) external onlyOwner validAddress(amm) {
        isAMM[amm] = status;
        isExcludedFromLimits[amm] = status; // AMMs são automaticamente isentos de limites
        emit AMMUpdated(amm, status, msg.sender);
    }

    // Ligar/desligar sistema de taxas
    function toggleTax(bool enabled) external onlyOwner {
        taxEnabled = enabled;
        emit TaxToggled(enabled, msg.sender);
    }

    // ============ FUNÇÕES DE VISUALIZAÇÃO ============
    // Funções para consultar dados do contrato
    
    // Obter informações de um lock específico
    function getLockInfo(uint256 lockId) external view returns (LiquidityLock memory) {
        require(lockId > 0 && lockId < nextLockId, "Invalid lock ID");
        return liquidityLocks[lockId];
    }

    // Obter lista de locks de um usuário
    function getUserLocks(address user) external view returns (uint256[] memory) {
        return userLocks[user];
    }

    // Verificar se um lock pode ser destravado
    function canUnlockLiquidity(uint256 lockId) external view returns (
        bool canUnlock, 
        uint256 timeRemaining, 
        bool isPermanent
    ) {
        require(lockId > 0 && lockId < nextLockId, "Invalid lock ID");
        
        LiquidityLock storage lock = liquidityLocks[lockId];
        if (!lock.isActive) return (false, 0, lock.isPermanent);
        if (lock.isPermanent) return (false, 0, true);
        
        if (block.timestamp >= lock.unlockTime) {
            return (true, 0, false);
        } else {
            return (false, lock.unlockTime - block.timestamp, false);
        }
    }

    // Obter informações de mudança pendente
    function getPendingChange(bytes32 changeId) external view returns (
        uint256 executeTime,
        uint256 param1,
        uint256 param2,
        address addr,
        bool exists,
        uint256 timeRemaining
    ) {
        PendingChange memory change = pendingChanges[changeId];
        uint256 remaining = 0;
        if (change.exists && block.timestamp < change.executeTime) {
            remaining = change.executeTime - block.timestamp;
        }
        return (change.executeTime, change.param1, change.param2, change.addr, change.exists, remaining);
    }

    // Obter informações gerais do token
    function getTokenInfo() external view returns (
        uint256 _maxSupply, // Supply máximo
        uint256 _totalSupply, // Supply atual
        bool _tradingEnabled, // Se trading está ativo
        uint256 _currentTaxRate, // Taxa atual
        uint256 _timeUntilNormalTax, // Tempo até taxa normal
        address _taxRecipient, // Destinatário da taxa
        bool _paused, // Se está pausado
        uint256 _totalLockedValue, // Valor total travado
        uint256 _totalPermanentLocks // Número de locks permanentes
    ) {
        uint256 timeLeft = 0;
        // Calcula tempo restante até taxa normal
        if (launchTime != 0 && block.timestamp < launchTime + INITIAL_TAX_PERIOD) {
            timeLeft = (launchTime + INITIAL_TAX_PERIOD) - block.timestamp;
        }

        return (
            MAX_SUPPLY,
            totalSupply(),
            tradingEnabled,
            getCurrentTaxRate(),
            timeLeft,
            taxRecipient,
            paused,
            totalLockedValue,
            totalPermanentLocks
        );
    }

    // Obter estatísticas de locks
    function getContractStats() external view returns (
        uint256 totalLocks, // Total de locks criados
        uint256 activeLocks, // Locks ativos
        uint256 permanentLocks, // Locks permanentes
        uint256 temporaryLocks, // Locks temporários
        uint256 totalValueLocked // Valor total travado
    ) {
        uint256 active = 0;
        uint256 temporary = 0;
        
        // Conta locks ativos e temporários
        for (uint256 i = 1; i < nextLockId; i++) {
            if (liquidityLocks[i].isActive) {
                active++;
                if (!liquidityLocks[i].isPermanent) {
                    temporary++;
                }
            }
        }

        return (
            nextLockId - 1,
            active,
            totalPermanentLocks,
            temporary,
            totalLockedValue
        );
    }

    // ============ FUNÇÕES DE EMERGÊNCIA ============
    // Para recuperar tokens enviados acidentalmente
    
    // Recuperar tokens ERC20 (exceto próprio token)
    function emergencyRecoverToken(
        address token, // Token a recuperar
        address to, // Destinatário
        uint256 amount // Quantidade
    ) external onlyOwner nonReentrant validAddress(to) {
        require(token != address(this), "Cannot recover own token");
        
        uint256 lockedAmount = lpTokenTotalLocked[token];
        uint256 contractBalance = IERC20(token).balanceOf(address(this));
        
        // Não pode recuperar tokens que estão travados
        require(
            lockedAmount == 0 || contractBalance - lockedAmount >= amount, 
            "Cannot recover locked tokens"
        );
        
        IERC20(token).transfer(to, amount);
        emit EmergencyRecovery(token, to, amount, msg.sender);
    }

    // Recuperar ETH enviado acidentalmente
    function emergencyRecoverETH(
        address payable to, 
        uint256 amount
    ) external onlyOwner nonReentrant validAddress(to) {
        require(amount <= address(this).balance, "Insufficient ETH balance");
        
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
        
        emit EmergencyRecovery(address(0), to, amount, msg.sender);
    }

    // Renunciar ownership permanentemente (irreversível)
    function renounceOwnershipPermanently() external onlyOwner {
        _transferOwnership(address(0)); // Transfer para endereço zero = renúncia
    }

    // ============ FUNÇÃO FALLBACK ============
    // Permite que o contrato receba ETH
    
    receive() external payable {
        // Aceita depósitos de ETH sem fazer nada
    }
}