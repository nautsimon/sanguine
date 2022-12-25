// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package destination

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// SystemContractAgentInfo is an auto generated low-level Go binding around an user-defined struct.
type SystemContractAgentInfo struct {
	Domain  uint32
	Account common.Address
	Bonded  bool
}

// AddressUpgradeableMetaData contains all meta data concerning the AddressUpgradeable contract.
var AddressUpgradeableMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122063227ed74336c074a8bb488da4408e50156bbd33122521e3d0c3ad11909fe18c64736f6c63430008110033",
}

// AddressUpgradeableABI is the input ABI used to generate the binding from.
// Deprecated: Use AddressUpgradeableMetaData.ABI instead.
var AddressUpgradeableABI = AddressUpgradeableMetaData.ABI

// AddressUpgradeableBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use AddressUpgradeableMetaData.Bin instead.
var AddressUpgradeableBin = AddressUpgradeableMetaData.Bin

// DeployAddressUpgradeable deploys a new Ethereum contract, binding an instance of AddressUpgradeable to it.
func DeployAddressUpgradeable(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *AddressUpgradeable, error) {
	parsed, err := AddressUpgradeableMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(AddressUpgradeableBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &AddressUpgradeable{AddressUpgradeableCaller: AddressUpgradeableCaller{contract: contract}, AddressUpgradeableTransactor: AddressUpgradeableTransactor{contract: contract}, AddressUpgradeableFilterer: AddressUpgradeableFilterer{contract: contract}}, nil
}

// AddressUpgradeable is an auto generated Go binding around an Ethereum contract.
type AddressUpgradeable struct {
	AddressUpgradeableCaller     // Read-only binding to the contract
	AddressUpgradeableTransactor // Write-only binding to the contract
	AddressUpgradeableFilterer   // Log filterer for contract events
}

// AddressUpgradeableCaller is an auto generated read-only Go binding around an Ethereum contract.
type AddressUpgradeableCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AddressUpgradeableTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AddressUpgradeableTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AddressUpgradeableFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AddressUpgradeableFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AddressUpgradeableSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AddressUpgradeableSession struct {
	Contract     *AddressUpgradeable // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// AddressUpgradeableCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AddressUpgradeableCallerSession struct {
	Contract *AddressUpgradeableCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// AddressUpgradeableTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AddressUpgradeableTransactorSession struct {
	Contract     *AddressUpgradeableTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// AddressUpgradeableRaw is an auto generated low-level Go binding around an Ethereum contract.
type AddressUpgradeableRaw struct {
	Contract *AddressUpgradeable // Generic contract binding to access the raw methods on
}

// AddressUpgradeableCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AddressUpgradeableCallerRaw struct {
	Contract *AddressUpgradeableCaller // Generic read-only contract binding to access the raw methods on
}

// AddressUpgradeableTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AddressUpgradeableTransactorRaw struct {
	Contract *AddressUpgradeableTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAddressUpgradeable creates a new instance of AddressUpgradeable, bound to a specific deployed contract.
func NewAddressUpgradeable(address common.Address, backend bind.ContractBackend) (*AddressUpgradeable, error) {
	contract, err := bindAddressUpgradeable(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AddressUpgradeable{AddressUpgradeableCaller: AddressUpgradeableCaller{contract: contract}, AddressUpgradeableTransactor: AddressUpgradeableTransactor{contract: contract}, AddressUpgradeableFilterer: AddressUpgradeableFilterer{contract: contract}}, nil
}

// NewAddressUpgradeableCaller creates a new read-only instance of AddressUpgradeable, bound to a specific deployed contract.
func NewAddressUpgradeableCaller(address common.Address, caller bind.ContractCaller) (*AddressUpgradeableCaller, error) {
	contract, err := bindAddressUpgradeable(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AddressUpgradeableCaller{contract: contract}, nil
}

// NewAddressUpgradeableTransactor creates a new write-only instance of AddressUpgradeable, bound to a specific deployed contract.
func NewAddressUpgradeableTransactor(address common.Address, transactor bind.ContractTransactor) (*AddressUpgradeableTransactor, error) {
	contract, err := bindAddressUpgradeable(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AddressUpgradeableTransactor{contract: contract}, nil
}

// NewAddressUpgradeableFilterer creates a new log filterer instance of AddressUpgradeable, bound to a specific deployed contract.
func NewAddressUpgradeableFilterer(address common.Address, filterer bind.ContractFilterer) (*AddressUpgradeableFilterer, error) {
	contract, err := bindAddressUpgradeable(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AddressUpgradeableFilterer{contract: contract}, nil
}

// bindAddressUpgradeable binds a generic wrapper to an already deployed contract.
func bindAddressUpgradeable(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AddressUpgradeableABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AddressUpgradeable *AddressUpgradeableRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AddressUpgradeable.Contract.AddressUpgradeableCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AddressUpgradeable *AddressUpgradeableRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AddressUpgradeable.Contract.AddressUpgradeableTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AddressUpgradeable *AddressUpgradeableRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AddressUpgradeable.Contract.AddressUpgradeableTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AddressUpgradeable *AddressUpgradeableCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AddressUpgradeable.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AddressUpgradeable *AddressUpgradeableTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AddressUpgradeable.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AddressUpgradeable *AddressUpgradeableTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AddressUpgradeable.Contract.contract.Transact(opts, method, params...)
}

// AgentRegistryMetaData contains all meta data concerning the AgentRegistry contract.
var AgentRegistryMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"allAgents\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"allDomains\",\"outputs\":[{\"internalType\":\"uint32[]\",\"name\":\"domains_\",\"type\":\"uint32[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"amountAgents\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"amountDomains\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"uint256\",\"name\":\"_agentIndex\",\"type\":\"uint256\"}],\"name\":\"getAgent\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_domainIndex\",\"type\":\"uint256\"}],\"name\":\"getDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"isActiveDomain\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"64ecb518": "allAgents(uint32)",
		"6f225878": "allDomains()",
		"32254098": "amountAgents(uint32)",
		"61b0b357": "amountDomains()",
		"1d82873b": "getAgent(uint32,uint256)",
		"1a7a98e2": "getDomain(uint256)",
		"65e1e466": "isActiveAgent(address)",
		"0958117d": "isActiveAgent(uint32,address)",
		"4f5dbc0d": "isActiveDomain(uint32)",
	},
}

// AgentRegistryABI is the input ABI used to generate the binding from.
// Deprecated: Use AgentRegistryMetaData.ABI instead.
var AgentRegistryABI = AgentRegistryMetaData.ABI

// Deprecated: Use AgentRegistryMetaData.Sigs instead.
// AgentRegistryFuncSigs maps the 4-byte function signature to its string representation.
var AgentRegistryFuncSigs = AgentRegistryMetaData.Sigs

// AgentRegistry is an auto generated Go binding around an Ethereum contract.
type AgentRegistry struct {
	AgentRegistryCaller     // Read-only binding to the contract
	AgentRegistryTransactor // Write-only binding to the contract
	AgentRegistryFilterer   // Log filterer for contract events
}

// AgentRegistryCaller is an auto generated read-only Go binding around an Ethereum contract.
type AgentRegistryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentRegistryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AgentRegistryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentRegistryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AgentRegistryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentRegistrySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AgentRegistrySession struct {
	Contract     *AgentRegistry    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AgentRegistryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AgentRegistryCallerSession struct {
	Contract *AgentRegistryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// AgentRegistryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AgentRegistryTransactorSession struct {
	Contract     *AgentRegistryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// AgentRegistryRaw is an auto generated low-level Go binding around an Ethereum contract.
type AgentRegistryRaw struct {
	Contract *AgentRegistry // Generic contract binding to access the raw methods on
}

// AgentRegistryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AgentRegistryCallerRaw struct {
	Contract *AgentRegistryCaller // Generic read-only contract binding to access the raw methods on
}

// AgentRegistryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AgentRegistryTransactorRaw struct {
	Contract *AgentRegistryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAgentRegistry creates a new instance of AgentRegistry, bound to a specific deployed contract.
func NewAgentRegistry(address common.Address, backend bind.ContractBackend) (*AgentRegistry, error) {
	contract, err := bindAgentRegistry(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AgentRegistry{AgentRegistryCaller: AgentRegistryCaller{contract: contract}, AgentRegistryTransactor: AgentRegistryTransactor{contract: contract}, AgentRegistryFilterer: AgentRegistryFilterer{contract: contract}}, nil
}

// NewAgentRegistryCaller creates a new read-only instance of AgentRegistry, bound to a specific deployed contract.
func NewAgentRegistryCaller(address common.Address, caller bind.ContractCaller) (*AgentRegistryCaller, error) {
	contract, err := bindAgentRegistry(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryCaller{contract: contract}, nil
}

// NewAgentRegistryTransactor creates a new write-only instance of AgentRegistry, bound to a specific deployed contract.
func NewAgentRegistryTransactor(address common.Address, transactor bind.ContractTransactor) (*AgentRegistryTransactor, error) {
	contract, err := bindAgentRegistry(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryTransactor{contract: contract}, nil
}

// NewAgentRegistryFilterer creates a new log filterer instance of AgentRegistry, bound to a specific deployed contract.
func NewAgentRegistryFilterer(address common.Address, filterer bind.ContractFilterer) (*AgentRegistryFilterer, error) {
	contract, err := bindAgentRegistry(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryFilterer{contract: contract}, nil
}

// bindAgentRegistry binds a generic wrapper to an already deployed contract.
func bindAgentRegistry(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AgentRegistryABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AgentRegistry *AgentRegistryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AgentRegistry.Contract.AgentRegistryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AgentRegistry *AgentRegistryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AgentRegistry.Contract.AgentRegistryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AgentRegistry *AgentRegistryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AgentRegistry.Contract.AgentRegistryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AgentRegistry *AgentRegistryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AgentRegistry.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AgentRegistry *AgentRegistryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AgentRegistry.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AgentRegistry *AgentRegistryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AgentRegistry.Contract.contract.Transact(opts, method, params...)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_AgentRegistry *AgentRegistryCaller) AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "allAgents", _domain)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_AgentRegistry *AgentRegistrySession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _AgentRegistry.Contract.AllAgents(&_AgentRegistry.CallOpts, _domain)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_AgentRegistry *AgentRegistryCallerSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _AgentRegistry.Contract.AllAgents(&_AgentRegistry.CallOpts, _domain)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_AgentRegistry *AgentRegistryCaller) AllDomains(opts *bind.CallOpts) ([]uint32, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "allDomains")

	if err != nil {
		return *new([]uint32), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint32)).(*[]uint32)

	return out0, err

}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_AgentRegistry *AgentRegistrySession) AllDomains() ([]uint32, error) {
	return _AgentRegistry.Contract.AllDomains(&_AgentRegistry.CallOpts)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_AgentRegistry *AgentRegistryCallerSession) AllDomains() ([]uint32, error) {
	return _AgentRegistry.Contract.AllDomains(&_AgentRegistry.CallOpts)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_AgentRegistry *AgentRegistryCaller) AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "amountAgents", _domain)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_AgentRegistry *AgentRegistrySession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _AgentRegistry.Contract.AmountAgents(&_AgentRegistry.CallOpts, _domain)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_AgentRegistry *AgentRegistryCallerSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _AgentRegistry.Contract.AmountAgents(&_AgentRegistry.CallOpts, _domain)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_AgentRegistry *AgentRegistryCaller) AmountDomains(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "amountDomains")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_AgentRegistry *AgentRegistrySession) AmountDomains() (*big.Int, error) {
	return _AgentRegistry.Contract.AmountDomains(&_AgentRegistry.CallOpts)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_AgentRegistry *AgentRegistryCallerSession) AmountDomains() (*big.Int, error) {
	return _AgentRegistry.Contract.AmountDomains(&_AgentRegistry.CallOpts)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_AgentRegistry *AgentRegistryCaller) GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "getAgent", _domain, _agentIndex)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_AgentRegistry *AgentRegistrySession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _AgentRegistry.Contract.GetAgent(&_AgentRegistry.CallOpts, _domain, _agentIndex)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_AgentRegistry *AgentRegistryCallerSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _AgentRegistry.Contract.GetAgent(&_AgentRegistry.CallOpts, _domain, _agentIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_AgentRegistry *AgentRegistryCaller) GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "getDomain", _domainIndex)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_AgentRegistry *AgentRegistrySession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _AgentRegistry.Contract.GetDomain(&_AgentRegistry.CallOpts, _domainIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_AgentRegistry *AgentRegistryCallerSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _AgentRegistry.Contract.GetDomain(&_AgentRegistry.CallOpts, _domainIndex)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_AgentRegistry *AgentRegistryCaller) IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "isActiveAgent", _domain, _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_AgentRegistry *AgentRegistrySession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _AgentRegistry.Contract.IsActiveAgent(&_AgentRegistry.CallOpts, _domain, _account)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_AgentRegistry *AgentRegistryCallerSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _AgentRegistry.Contract.IsActiveAgent(&_AgentRegistry.CallOpts, _domain, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_AgentRegistry *AgentRegistryCaller) IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "isActiveAgent0", _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_AgentRegistry *AgentRegistrySession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _AgentRegistry.Contract.IsActiveAgent0(&_AgentRegistry.CallOpts, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_AgentRegistry *AgentRegistryCallerSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _AgentRegistry.Contract.IsActiveAgent0(&_AgentRegistry.CallOpts, _account)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_AgentRegistry *AgentRegistryCaller) IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error) {
	var out []interface{}
	err := _AgentRegistry.contract.Call(opts, &out, "isActiveDomain", _domain)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_AgentRegistry *AgentRegistrySession) IsActiveDomain(_domain uint32) (bool, error) {
	return _AgentRegistry.Contract.IsActiveDomain(&_AgentRegistry.CallOpts, _domain)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_AgentRegistry *AgentRegistryCallerSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _AgentRegistry.Contract.IsActiveDomain(&_AgentRegistry.CallOpts, _domain)
}

// AgentRegistryAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the AgentRegistry contract.
type AgentRegistryAgentAddedIterator struct {
	Event *AgentRegistryAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryAgentAdded represents a AgentAdded event raised by the AgentRegistry contract.
type AgentRegistryAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AgentRegistry *AgentRegistryFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*AgentRegistryAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistry.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryAgentAddedIterator{contract: _AgentRegistry.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AgentRegistry *AgentRegistryFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *AgentRegistryAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistry.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryAgentAdded)
				if err := _AgentRegistry.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AgentRegistry *AgentRegistryFilterer) ParseAgentAdded(log types.Log) (*AgentRegistryAgentAdded, error) {
	event := new(AgentRegistryAgentAdded)
	if err := _AgentRegistry.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the AgentRegistry contract.
type AgentRegistryAgentRemovedIterator struct {
	Event *AgentRegistryAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryAgentRemoved represents a AgentRemoved event raised by the AgentRegistry contract.
type AgentRegistryAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AgentRegistry *AgentRegistryFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*AgentRegistryAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistry.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryAgentRemovedIterator{contract: _AgentRegistry.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AgentRegistry *AgentRegistryFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *AgentRegistryAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistry.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryAgentRemoved)
				if err := _AgentRegistry.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AgentRegistry *AgentRegistryFilterer) ParseAgentRemoved(log types.Log) (*AgentRegistryAgentRemoved, error) {
	event := new(AgentRegistryAgentRemoved)
	if err := _AgentRegistry.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the AgentRegistry contract.
type AgentRegistryDomainActivatedIterator struct {
	Event *AgentRegistryDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryDomainActivated represents a DomainActivated event raised by the AgentRegistry contract.
type AgentRegistryDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AgentRegistry *AgentRegistryFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*AgentRegistryDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistry.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryDomainActivatedIterator{contract: _AgentRegistry.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AgentRegistry *AgentRegistryFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *AgentRegistryDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistry.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryDomainActivated)
				if err := _AgentRegistry.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AgentRegistry *AgentRegistryFilterer) ParseDomainActivated(log types.Log) (*AgentRegistryDomainActivated, error) {
	event := new(AgentRegistryDomainActivated)
	if err := _AgentRegistry.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the AgentRegistry contract.
type AgentRegistryDomainDeactivatedIterator struct {
	Event *AgentRegistryDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryDomainDeactivated represents a DomainDeactivated event raised by the AgentRegistry contract.
type AgentRegistryDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AgentRegistry *AgentRegistryFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*AgentRegistryDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistry.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryDomainDeactivatedIterator{contract: _AgentRegistry.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AgentRegistry *AgentRegistryFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *AgentRegistryDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistry.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryDomainDeactivated)
				if err := _AgentRegistry.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AgentRegistry *AgentRegistryFilterer) ParseDomainDeactivated(log types.Log) (*AgentRegistryDomainDeactivated, error) {
	event := new(AgentRegistryDomainDeactivated)
	if err := _AgentRegistry.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryEventsMetaData contains all meta data concerning the AgentRegistryEvents contract.
var AgentRegistryEventsMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"}]",
}

// AgentRegistryEventsABI is the input ABI used to generate the binding from.
// Deprecated: Use AgentRegistryEventsMetaData.ABI instead.
var AgentRegistryEventsABI = AgentRegistryEventsMetaData.ABI

// AgentRegistryEvents is an auto generated Go binding around an Ethereum contract.
type AgentRegistryEvents struct {
	AgentRegistryEventsCaller     // Read-only binding to the contract
	AgentRegistryEventsTransactor // Write-only binding to the contract
	AgentRegistryEventsFilterer   // Log filterer for contract events
}

// AgentRegistryEventsCaller is an auto generated read-only Go binding around an Ethereum contract.
type AgentRegistryEventsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentRegistryEventsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AgentRegistryEventsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentRegistryEventsFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AgentRegistryEventsFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentRegistryEventsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AgentRegistryEventsSession struct {
	Contract     *AgentRegistryEvents // Generic contract binding to set the session for
	CallOpts     bind.CallOpts        // Call options to use throughout this session
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// AgentRegistryEventsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AgentRegistryEventsCallerSession struct {
	Contract *AgentRegistryEventsCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts              // Call options to use throughout this session
}

// AgentRegistryEventsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AgentRegistryEventsTransactorSession struct {
	Contract     *AgentRegistryEventsTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts              // Transaction auth options to use throughout this session
}

// AgentRegistryEventsRaw is an auto generated low-level Go binding around an Ethereum contract.
type AgentRegistryEventsRaw struct {
	Contract *AgentRegistryEvents // Generic contract binding to access the raw methods on
}

// AgentRegistryEventsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AgentRegistryEventsCallerRaw struct {
	Contract *AgentRegistryEventsCaller // Generic read-only contract binding to access the raw methods on
}

// AgentRegistryEventsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AgentRegistryEventsTransactorRaw struct {
	Contract *AgentRegistryEventsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAgentRegistryEvents creates a new instance of AgentRegistryEvents, bound to a specific deployed contract.
func NewAgentRegistryEvents(address common.Address, backend bind.ContractBackend) (*AgentRegistryEvents, error) {
	contract, err := bindAgentRegistryEvents(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEvents{AgentRegistryEventsCaller: AgentRegistryEventsCaller{contract: contract}, AgentRegistryEventsTransactor: AgentRegistryEventsTransactor{contract: contract}, AgentRegistryEventsFilterer: AgentRegistryEventsFilterer{contract: contract}}, nil
}

// NewAgentRegistryEventsCaller creates a new read-only instance of AgentRegistryEvents, bound to a specific deployed contract.
func NewAgentRegistryEventsCaller(address common.Address, caller bind.ContractCaller) (*AgentRegistryEventsCaller, error) {
	contract, err := bindAgentRegistryEvents(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsCaller{contract: contract}, nil
}

// NewAgentRegistryEventsTransactor creates a new write-only instance of AgentRegistryEvents, bound to a specific deployed contract.
func NewAgentRegistryEventsTransactor(address common.Address, transactor bind.ContractTransactor) (*AgentRegistryEventsTransactor, error) {
	contract, err := bindAgentRegistryEvents(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsTransactor{contract: contract}, nil
}

// NewAgentRegistryEventsFilterer creates a new log filterer instance of AgentRegistryEvents, bound to a specific deployed contract.
func NewAgentRegistryEventsFilterer(address common.Address, filterer bind.ContractFilterer) (*AgentRegistryEventsFilterer, error) {
	contract, err := bindAgentRegistryEvents(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsFilterer{contract: contract}, nil
}

// bindAgentRegistryEvents binds a generic wrapper to an already deployed contract.
func bindAgentRegistryEvents(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AgentRegistryEventsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AgentRegistryEvents *AgentRegistryEventsRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AgentRegistryEvents.Contract.AgentRegistryEventsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AgentRegistryEvents *AgentRegistryEventsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AgentRegistryEvents.Contract.AgentRegistryEventsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AgentRegistryEvents *AgentRegistryEventsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AgentRegistryEvents.Contract.AgentRegistryEventsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AgentRegistryEvents *AgentRegistryEventsCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AgentRegistryEvents.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AgentRegistryEvents *AgentRegistryEventsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AgentRegistryEvents.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AgentRegistryEvents *AgentRegistryEventsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AgentRegistryEvents.Contract.contract.Transact(opts, method, params...)
}

// AgentRegistryEventsAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the AgentRegistryEvents contract.
type AgentRegistryEventsAgentAddedIterator struct {
	Event *AgentRegistryEventsAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryEventsAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryEventsAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryEventsAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryEventsAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryEventsAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryEventsAgentAdded represents a AgentAdded event raised by the AgentRegistryEvents contract.
type AgentRegistryEventsAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*AgentRegistryEventsAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsAgentAddedIterator{contract: _AgentRegistryEvents.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *AgentRegistryEventsAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryEventsAgentAdded)
				if err := _AgentRegistryEvents.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) ParseAgentAdded(log types.Log) (*AgentRegistryEventsAgentAdded, error) {
	event := new(AgentRegistryEventsAgentAdded)
	if err := _AgentRegistryEvents.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryEventsAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the AgentRegistryEvents contract.
type AgentRegistryEventsAgentRemovedIterator struct {
	Event *AgentRegistryEventsAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryEventsAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryEventsAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryEventsAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryEventsAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryEventsAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryEventsAgentRemoved represents a AgentRemoved event raised by the AgentRegistryEvents contract.
type AgentRegistryEventsAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*AgentRegistryEventsAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsAgentRemovedIterator{contract: _AgentRegistryEvents.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *AgentRegistryEventsAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryEventsAgentRemoved)
				if err := _AgentRegistryEvents.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) ParseAgentRemoved(log types.Log) (*AgentRegistryEventsAgentRemoved, error) {
	event := new(AgentRegistryEventsAgentRemoved)
	if err := _AgentRegistryEvents.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryEventsDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the AgentRegistryEvents contract.
type AgentRegistryEventsDomainActivatedIterator struct {
	Event *AgentRegistryEventsDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryEventsDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryEventsDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryEventsDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryEventsDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryEventsDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryEventsDomainActivated represents a DomainActivated event raised by the AgentRegistryEvents contract.
type AgentRegistryEventsDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*AgentRegistryEventsDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsDomainActivatedIterator{contract: _AgentRegistryEvents.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *AgentRegistryEventsDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryEventsDomainActivated)
				if err := _AgentRegistryEvents.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) ParseDomainActivated(log types.Log) (*AgentRegistryEventsDomainActivated, error) {
	event := new(AgentRegistryEventsDomainActivated)
	if err := _AgentRegistryEvents.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentRegistryEventsDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the AgentRegistryEvents contract.
type AgentRegistryEventsDomainDeactivatedIterator struct {
	Event *AgentRegistryEventsDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AgentRegistryEventsDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AgentRegistryEventsDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AgentRegistryEventsDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AgentRegistryEventsDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AgentRegistryEventsDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AgentRegistryEventsDomainDeactivated represents a DomainDeactivated event raised by the AgentRegistryEvents contract.
type AgentRegistryEventsDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*AgentRegistryEventsDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &AgentRegistryEventsDomainDeactivatedIterator{contract: _AgentRegistryEvents.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *AgentRegistryEventsDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AgentRegistryEvents.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AgentRegistryEventsDomainDeactivated)
				if err := _AgentRegistryEvents.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AgentRegistryEvents *AgentRegistryEventsFilterer) ParseDomainDeactivated(log types.Log) (*AgentRegistryEventsDomainDeactivated, error) {
	event := new(AgentRegistryEventsDomainDeactivated)
	if err := _AgentRegistryEvents.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AgentSetMetaData contains all meta data concerning the AgentSet contract.
var AgentSetMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122000ec0c5b28fdb6d7907eb195944d59f36b9c54a5630e380a051ebf09f6d69c5e64736f6c63430008110033",
}

// AgentSetABI is the input ABI used to generate the binding from.
// Deprecated: Use AgentSetMetaData.ABI instead.
var AgentSetABI = AgentSetMetaData.ABI

// AgentSetBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use AgentSetMetaData.Bin instead.
var AgentSetBin = AgentSetMetaData.Bin

// DeployAgentSet deploys a new Ethereum contract, binding an instance of AgentSet to it.
func DeployAgentSet(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *AgentSet, error) {
	parsed, err := AgentSetMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(AgentSetBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &AgentSet{AgentSetCaller: AgentSetCaller{contract: contract}, AgentSetTransactor: AgentSetTransactor{contract: contract}, AgentSetFilterer: AgentSetFilterer{contract: contract}}, nil
}

// AgentSet is an auto generated Go binding around an Ethereum contract.
type AgentSet struct {
	AgentSetCaller     // Read-only binding to the contract
	AgentSetTransactor // Write-only binding to the contract
	AgentSetFilterer   // Log filterer for contract events
}

// AgentSetCaller is an auto generated read-only Go binding around an Ethereum contract.
type AgentSetCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentSetTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AgentSetTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentSetFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AgentSetFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AgentSetSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AgentSetSession struct {
	Contract     *AgentSet         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AgentSetCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AgentSetCallerSession struct {
	Contract *AgentSetCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// AgentSetTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AgentSetTransactorSession struct {
	Contract     *AgentSetTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// AgentSetRaw is an auto generated low-level Go binding around an Ethereum contract.
type AgentSetRaw struct {
	Contract *AgentSet // Generic contract binding to access the raw methods on
}

// AgentSetCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AgentSetCallerRaw struct {
	Contract *AgentSetCaller // Generic read-only contract binding to access the raw methods on
}

// AgentSetTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AgentSetTransactorRaw struct {
	Contract *AgentSetTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAgentSet creates a new instance of AgentSet, bound to a specific deployed contract.
func NewAgentSet(address common.Address, backend bind.ContractBackend) (*AgentSet, error) {
	contract, err := bindAgentSet(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AgentSet{AgentSetCaller: AgentSetCaller{contract: contract}, AgentSetTransactor: AgentSetTransactor{contract: contract}, AgentSetFilterer: AgentSetFilterer{contract: contract}}, nil
}

// NewAgentSetCaller creates a new read-only instance of AgentSet, bound to a specific deployed contract.
func NewAgentSetCaller(address common.Address, caller bind.ContractCaller) (*AgentSetCaller, error) {
	contract, err := bindAgentSet(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AgentSetCaller{contract: contract}, nil
}

// NewAgentSetTransactor creates a new write-only instance of AgentSet, bound to a specific deployed contract.
func NewAgentSetTransactor(address common.Address, transactor bind.ContractTransactor) (*AgentSetTransactor, error) {
	contract, err := bindAgentSet(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AgentSetTransactor{contract: contract}, nil
}

// NewAgentSetFilterer creates a new log filterer instance of AgentSet, bound to a specific deployed contract.
func NewAgentSetFilterer(address common.Address, filterer bind.ContractFilterer) (*AgentSetFilterer, error) {
	contract, err := bindAgentSet(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AgentSetFilterer{contract: contract}, nil
}

// bindAgentSet binds a generic wrapper to an already deployed contract.
func bindAgentSet(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AgentSetABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AgentSet *AgentSetRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AgentSet.Contract.AgentSetCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AgentSet *AgentSetRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AgentSet.Contract.AgentSetTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AgentSet *AgentSetRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AgentSet.Contract.AgentSetTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AgentSet *AgentSetCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AgentSet.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AgentSet *AgentSetTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AgentSet.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AgentSet *AgentSetTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AgentSet.Contract.contract.Transact(opts, method, params...)
}

// AttestationMetaData contains all meta data concerning the Attestation contract.
var AttestationMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea2646970667358221220e07a56642093e1b2185e28bff9946fe6b0b1d7a700896d47457e1ada5b1aff2264736f6c63430008110033",
}

// AttestationABI is the input ABI used to generate the binding from.
// Deprecated: Use AttestationMetaData.ABI instead.
var AttestationABI = AttestationMetaData.ABI

// AttestationBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use AttestationMetaData.Bin instead.
var AttestationBin = AttestationMetaData.Bin

// DeployAttestation deploys a new Ethereum contract, binding an instance of Attestation to it.
func DeployAttestation(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Attestation, error) {
	parsed, err := AttestationMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(AttestationBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Attestation{AttestationCaller: AttestationCaller{contract: contract}, AttestationTransactor: AttestationTransactor{contract: contract}, AttestationFilterer: AttestationFilterer{contract: contract}}, nil
}

// Attestation is an auto generated Go binding around an Ethereum contract.
type Attestation struct {
	AttestationCaller     // Read-only binding to the contract
	AttestationTransactor // Write-only binding to the contract
	AttestationFilterer   // Log filterer for contract events
}

// AttestationCaller is an auto generated read-only Go binding around an Ethereum contract.
type AttestationCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AttestationTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AttestationFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AttestationSession struct {
	Contract     *Attestation      // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AttestationCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AttestationCallerSession struct {
	Contract *AttestationCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts      // Call options to use throughout this session
}

// AttestationTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AttestationTransactorSession struct {
	Contract     *AttestationTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// AttestationRaw is an auto generated low-level Go binding around an Ethereum contract.
type AttestationRaw struct {
	Contract *Attestation // Generic contract binding to access the raw methods on
}

// AttestationCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AttestationCallerRaw struct {
	Contract *AttestationCaller // Generic read-only contract binding to access the raw methods on
}

// AttestationTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AttestationTransactorRaw struct {
	Contract *AttestationTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAttestation creates a new instance of Attestation, bound to a specific deployed contract.
func NewAttestation(address common.Address, backend bind.ContractBackend) (*Attestation, error) {
	contract, err := bindAttestation(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Attestation{AttestationCaller: AttestationCaller{contract: contract}, AttestationTransactor: AttestationTransactor{contract: contract}, AttestationFilterer: AttestationFilterer{contract: contract}}, nil
}

// NewAttestationCaller creates a new read-only instance of Attestation, bound to a specific deployed contract.
func NewAttestationCaller(address common.Address, caller bind.ContractCaller) (*AttestationCaller, error) {
	contract, err := bindAttestation(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AttestationCaller{contract: contract}, nil
}

// NewAttestationTransactor creates a new write-only instance of Attestation, bound to a specific deployed contract.
func NewAttestationTransactor(address common.Address, transactor bind.ContractTransactor) (*AttestationTransactor, error) {
	contract, err := bindAttestation(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AttestationTransactor{contract: contract}, nil
}

// NewAttestationFilterer creates a new log filterer instance of Attestation, bound to a specific deployed contract.
func NewAttestationFilterer(address common.Address, filterer bind.ContractFilterer) (*AttestationFilterer, error) {
	contract, err := bindAttestation(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AttestationFilterer{contract: contract}, nil
}

// bindAttestation binds a generic wrapper to an already deployed contract.
func bindAttestation(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AttestationABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Attestation *AttestationRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Attestation.Contract.AttestationCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Attestation *AttestationRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Attestation.Contract.AttestationTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Attestation *AttestationRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Attestation.Contract.AttestationTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Attestation *AttestationCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Attestation.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Attestation *AttestationTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Attestation.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Attestation *AttestationTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Attestation.Contract.contract.Transact(opts, method, params...)
}

// AttestationHubMetaData contains all meta data concerning the AttestationHub contract.
var AttestationHubMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"guards\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"notaries\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"attestation\",\"type\":\"bytes\"}],\"name\":\"AttestationAccepted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"allAgents\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"allDomains\",\"outputs\":[{\"internalType\":\"uint32[]\",\"name\":\"domains_\",\"type\":\"uint32[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"amountAgents\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"amountDomains\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"uint256\",\"name\":\"_agentIndex\",\"type\":\"uint256\"}],\"name\":\"getAgent\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_domainIndex\",\"type\":\"uint256\"}],\"name\":\"getDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"isActiveDomain\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_attestation\",\"type\":\"bytes\"}],\"name\":\"submitAttestation\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"64ecb518": "allAgents(uint32)",
		"6f225878": "allDomains()",
		"32254098": "amountAgents(uint32)",
		"61b0b357": "amountDomains()",
		"1d82873b": "getAgent(uint32,uint256)",
		"1a7a98e2": "getDomain(uint256)",
		"65e1e466": "isActiveAgent(address)",
		"0958117d": "isActiveAgent(uint32,address)",
		"4f5dbc0d": "isActiveDomain(uint32)",
		"f646a512": "submitAttestation(bytes)",
	},
}

// AttestationHubABI is the input ABI used to generate the binding from.
// Deprecated: Use AttestationHubMetaData.ABI instead.
var AttestationHubABI = AttestationHubMetaData.ABI

// Deprecated: Use AttestationHubMetaData.Sigs instead.
// AttestationHubFuncSigs maps the 4-byte function signature to its string representation.
var AttestationHubFuncSigs = AttestationHubMetaData.Sigs

// AttestationHub is an auto generated Go binding around an Ethereum contract.
type AttestationHub struct {
	AttestationHubCaller     // Read-only binding to the contract
	AttestationHubTransactor // Write-only binding to the contract
	AttestationHubFilterer   // Log filterer for contract events
}

// AttestationHubCaller is an auto generated read-only Go binding around an Ethereum contract.
type AttestationHubCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationHubTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AttestationHubTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationHubFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AttestationHubFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationHubSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AttestationHubSession struct {
	Contract     *AttestationHub   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AttestationHubCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AttestationHubCallerSession struct {
	Contract *AttestationHubCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// AttestationHubTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AttestationHubTransactorSession struct {
	Contract     *AttestationHubTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// AttestationHubRaw is an auto generated low-level Go binding around an Ethereum contract.
type AttestationHubRaw struct {
	Contract *AttestationHub // Generic contract binding to access the raw methods on
}

// AttestationHubCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AttestationHubCallerRaw struct {
	Contract *AttestationHubCaller // Generic read-only contract binding to access the raw methods on
}

// AttestationHubTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AttestationHubTransactorRaw struct {
	Contract *AttestationHubTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAttestationHub creates a new instance of AttestationHub, bound to a specific deployed contract.
func NewAttestationHub(address common.Address, backend bind.ContractBackend) (*AttestationHub, error) {
	contract, err := bindAttestationHub(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AttestationHub{AttestationHubCaller: AttestationHubCaller{contract: contract}, AttestationHubTransactor: AttestationHubTransactor{contract: contract}, AttestationHubFilterer: AttestationHubFilterer{contract: contract}}, nil
}

// NewAttestationHubCaller creates a new read-only instance of AttestationHub, bound to a specific deployed contract.
func NewAttestationHubCaller(address common.Address, caller bind.ContractCaller) (*AttestationHubCaller, error) {
	contract, err := bindAttestationHub(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AttestationHubCaller{contract: contract}, nil
}

// NewAttestationHubTransactor creates a new write-only instance of AttestationHub, bound to a specific deployed contract.
func NewAttestationHubTransactor(address common.Address, transactor bind.ContractTransactor) (*AttestationHubTransactor, error) {
	contract, err := bindAttestationHub(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AttestationHubTransactor{contract: contract}, nil
}

// NewAttestationHubFilterer creates a new log filterer instance of AttestationHub, bound to a specific deployed contract.
func NewAttestationHubFilterer(address common.Address, filterer bind.ContractFilterer) (*AttestationHubFilterer, error) {
	contract, err := bindAttestationHub(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AttestationHubFilterer{contract: contract}, nil
}

// bindAttestationHub binds a generic wrapper to an already deployed contract.
func bindAttestationHub(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AttestationHubABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AttestationHub *AttestationHubRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AttestationHub.Contract.AttestationHubCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AttestationHub *AttestationHubRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AttestationHub.Contract.AttestationHubTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AttestationHub *AttestationHubRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AttestationHub.Contract.AttestationHubTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AttestationHub *AttestationHubCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AttestationHub.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AttestationHub *AttestationHubTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AttestationHub.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AttestationHub *AttestationHubTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AttestationHub.Contract.contract.Transact(opts, method, params...)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_AttestationHub *AttestationHubCaller) AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "allAgents", _domain)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_AttestationHub *AttestationHubSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _AttestationHub.Contract.AllAgents(&_AttestationHub.CallOpts, _domain)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_AttestationHub *AttestationHubCallerSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _AttestationHub.Contract.AllAgents(&_AttestationHub.CallOpts, _domain)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_AttestationHub *AttestationHubCaller) AllDomains(opts *bind.CallOpts) ([]uint32, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "allDomains")

	if err != nil {
		return *new([]uint32), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint32)).(*[]uint32)

	return out0, err

}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_AttestationHub *AttestationHubSession) AllDomains() ([]uint32, error) {
	return _AttestationHub.Contract.AllDomains(&_AttestationHub.CallOpts)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_AttestationHub *AttestationHubCallerSession) AllDomains() ([]uint32, error) {
	return _AttestationHub.Contract.AllDomains(&_AttestationHub.CallOpts)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_AttestationHub *AttestationHubCaller) AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "amountAgents", _domain)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_AttestationHub *AttestationHubSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _AttestationHub.Contract.AmountAgents(&_AttestationHub.CallOpts, _domain)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_AttestationHub *AttestationHubCallerSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _AttestationHub.Contract.AmountAgents(&_AttestationHub.CallOpts, _domain)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_AttestationHub *AttestationHubCaller) AmountDomains(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "amountDomains")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_AttestationHub *AttestationHubSession) AmountDomains() (*big.Int, error) {
	return _AttestationHub.Contract.AmountDomains(&_AttestationHub.CallOpts)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_AttestationHub *AttestationHubCallerSession) AmountDomains() (*big.Int, error) {
	return _AttestationHub.Contract.AmountDomains(&_AttestationHub.CallOpts)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_AttestationHub *AttestationHubCaller) GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "getAgent", _domain, _agentIndex)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_AttestationHub *AttestationHubSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _AttestationHub.Contract.GetAgent(&_AttestationHub.CallOpts, _domain, _agentIndex)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_AttestationHub *AttestationHubCallerSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _AttestationHub.Contract.GetAgent(&_AttestationHub.CallOpts, _domain, _agentIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_AttestationHub *AttestationHubCaller) GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "getDomain", _domainIndex)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_AttestationHub *AttestationHubSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _AttestationHub.Contract.GetDomain(&_AttestationHub.CallOpts, _domainIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_AttestationHub *AttestationHubCallerSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _AttestationHub.Contract.GetDomain(&_AttestationHub.CallOpts, _domainIndex)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_AttestationHub *AttestationHubCaller) IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "isActiveAgent", _domain, _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_AttestationHub *AttestationHubSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _AttestationHub.Contract.IsActiveAgent(&_AttestationHub.CallOpts, _domain, _account)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_AttestationHub *AttestationHubCallerSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _AttestationHub.Contract.IsActiveAgent(&_AttestationHub.CallOpts, _domain, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_AttestationHub *AttestationHubCaller) IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "isActiveAgent0", _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_AttestationHub *AttestationHubSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _AttestationHub.Contract.IsActiveAgent0(&_AttestationHub.CallOpts, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_AttestationHub *AttestationHubCallerSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _AttestationHub.Contract.IsActiveAgent0(&_AttestationHub.CallOpts, _account)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_AttestationHub *AttestationHubCaller) IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error) {
	var out []interface{}
	err := _AttestationHub.contract.Call(opts, &out, "isActiveDomain", _domain)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_AttestationHub *AttestationHubSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _AttestationHub.Contract.IsActiveDomain(&_AttestationHub.CallOpts, _domain)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_AttestationHub *AttestationHubCallerSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _AttestationHub.Contract.IsActiveDomain(&_AttestationHub.CallOpts, _domain)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_AttestationHub *AttestationHubTransactor) SubmitAttestation(opts *bind.TransactOpts, _attestation []byte) (*types.Transaction, error) {
	return _AttestationHub.contract.Transact(opts, "submitAttestation", _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_AttestationHub *AttestationHubSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _AttestationHub.Contract.SubmitAttestation(&_AttestationHub.TransactOpts, _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_AttestationHub *AttestationHubTransactorSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _AttestationHub.Contract.SubmitAttestation(&_AttestationHub.TransactOpts, _attestation)
}

// AttestationHubAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the AttestationHub contract.
type AttestationHubAgentAddedIterator struct {
	Event *AttestationHubAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AttestationHubAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AttestationHubAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AttestationHubAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AttestationHubAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AttestationHubAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AttestationHubAgentAdded represents a AgentAdded event raised by the AttestationHub contract.
type AttestationHubAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AttestationHub *AttestationHubFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*AttestationHubAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AttestationHub.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &AttestationHubAgentAddedIterator{contract: _AttestationHub.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AttestationHub *AttestationHubFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *AttestationHubAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AttestationHub.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AttestationHubAgentAdded)
				if err := _AttestationHub.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_AttestationHub *AttestationHubFilterer) ParseAgentAdded(log types.Log) (*AttestationHubAgentAdded, error) {
	event := new(AttestationHubAgentAdded)
	if err := _AttestationHub.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AttestationHubAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the AttestationHub contract.
type AttestationHubAgentRemovedIterator struct {
	Event *AttestationHubAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AttestationHubAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AttestationHubAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AttestationHubAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AttestationHubAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AttestationHubAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AttestationHubAgentRemoved represents a AgentRemoved event raised by the AttestationHub contract.
type AttestationHubAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AttestationHub *AttestationHubFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*AttestationHubAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AttestationHub.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &AttestationHubAgentRemovedIterator{contract: _AttestationHub.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AttestationHub *AttestationHubFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *AttestationHubAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _AttestationHub.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AttestationHubAgentRemoved)
				if err := _AttestationHub.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_AttestationHub *AttestationHubFilterer) ParseAgentRemoved(log types.Log) (*AttestationHubAgentRemoved, error) {
	event := new(AttestationHubAgentRemoved)
	if err := _AttestationHub.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AttestationHubAttestationAcceptedIterator is returned from FilterAttestationAccepted and is used to iterate over the raw logs and unpacked data for AttestationAccepted events raised by the AttestationHub contract.
type AttestationHubAttestationAcceptedIterator struct {
	Event *AttestationHubAttestationAccepted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AttestationHubAttestationAcceptedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AttestationHubAttestationAccepted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AttestationHubAttestationAccepted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AttestationHubAttestationAcceptedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AttestationHubAttestationAcceptedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AttestationHubAttestationAccepted represents a AttestationAccepted event raised by the AttestationHub contract.
type AttestationHubAttestationAccepted struct {
	Guards      []common.Address
	Notaries    []common.Address
	Attestation []byte
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterAttestationAccepted is a free log retrieval operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_AttestationHub *AttestationHubFilterer) FilterAttestationAccepted(opts *bind.FilterOpts) (*AttestationHubAttestationAcceptedIterator, error) {

	logs, sub, err := _AttestationHub.contract.FilterLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return &AttestationHubAttestationAcceptedIterator{contract: _AttestationHub.contract, event: "AttestationAccepted", logs: logs, sub: sub}, nil
}

// WatchAttestationAccepted is a free log subscription operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_AttestationHub *AttestationHubFilterer) WatchAttestationAccepted(opts *bind.WatchOpts, sink chan<- *AttestationHubAttestationAccepted) (event.Subscription, error) {

	logs, sub, err := _AttestationHub.contract.WatchLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AttestationHubAttestationAccepted)
				if err := _AttestationHub.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAttestationAccepted is a log parse operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_AttestationHub *AttestationHubFilterer) ParseAttestationAccepted(log types.Log) (*AttestationHubAttestationAccepted, error) {
	event := new(AttestationHubAttestationAccepted)
	if err := _AttestationHub.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AttestationHubDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the AttestationHub contract.
type AttestationHubDomainActivatedIterator struct {
	Event *AttestationHubDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AttestationHubDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AttestationHubDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AttestationHubDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AttestationHubDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AttestationHubDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AttestationHubDomainActivated represents a DomainActivated event raised by the AttestationHub contract.
type AttestationHubDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AttestationHub *AttestationHubFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*AttestationHubDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AttestationHub.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &AttestationHubDomainActivatedIterator{contract: _AttestationHub.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AttestationHub *AttestationHubFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *AttestationHubDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AttestationHub.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AttestationHubDomainActivated)
				if err := _AttestationHub.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_AttestationHub *AttestationHubFilterer) ParseDomainActivated(log types.Log) (*AttestationHubDomainActivated, error) {
	event := new(AttestationHubDomainActivated)
	if err := _AttestationHub.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AttestationHubDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the AttestationHub contract.
type AttestationHubDomainDeactivatedIterator struct {
	Event *AttestationHubDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AttestationHubDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AttestationHubDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AttestationHubDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AttestationHubDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AttestationHubDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AttestationHubDomainDeactivated represents a DomainDeactivated event raised by the AttestationHub contract.
type AttestationHubDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AttestationHub *AttestationHubFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*AttestationHubDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AttestationHub.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &AttestationHubDomainDeactivatedIterator{contract: _AttestationHub.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AttestationHub *AttestationHubFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *AttestationHubDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _AttestationHub.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AttestationHubDomainDeactivated)
				if err := _AttestationHub.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_AttestationHub *AttestationHubFilterer) ParseDomainDeactivated(log types.Log) (*AttestationHubDomainDeactivated, error) {
	event := new(AttestationHubDomainDeactivated)
	if err := _AttestationHub.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AttestationHubEventsMetaData contains all meta data concerning the AttestationHubEvents contract.
var AttestationHubEventsMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"guards\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"notaries\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"attestation\",\"type\":\"bytes\"}],\"name\":\"AttestationAccepted\",\"type\":\"event\"}]",
}

// AttestationHubEventsABI is the input ABI used to generate the binding from.
// Deprecated: Use AttestationHubEventsMetaData.ABI instead.
var AttestationHubEventsABI = AttestationHubEventsMetaData.ABI

// AttestationHubEvents is an auto generated Go binding around an Ethereum contract.
type AttestationHubEvents struct {
	AttestationHubEventsCaller     // Read-only binding to the contract
	AttestationHubEventsTransactor // Write-only binding to the contract
	AttestationHubEventsFilterer   // Log filterer for contract events
}

// AttestationHubEventsCaller is an auto generated read-only Go binding around an Ethereum contract.
type AttestationHubEventsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationHubEventsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AttestationHubEventsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationHubEventsFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AttestationHubEventsFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AttestationHubEventsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AttestationHubEventsSession struct {
	Contract     *AttestationHubEvents // Generic contract binding to set the session for
	CallOpts     bind.CallOpts         // Call options to use throughout this session
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// AttestationHubEventsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AttestationHubEventsCallerSession struct {
	Contract *AttestationHubEventsCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts               // Call options to use throughout this session
}

// AttestationHubEventsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AttestationHubEventsTransactorSession struct {
	Contract     *AttestationHubEventsTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts               // Transaction auth options to use throughout this session
}

// AttestationHubEventsRaw is an auto generated low-level Go binding around an Ethereum contract.
type AttestationHubEventsRaw struct {
	Contract *AttestationHubEvents // Generic contract binding to access the raw methods on
}

// AttestationHubEventsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AttestationHubEventsCallerRaw struct {
	Contract *AttestationHubEventsCaller // Generic read-only contract binding to access the raw methods on
}

// AttestationHubEventsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AttestationHubEventsTransactorRaw struct {
	Contract *AttestationHubEventsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAttestationHubEvents creates a new instance of AttestationHubEvents, bound to a specific deployed contract.
func NewAttestationHubEvents(address common.Address, backend bind.ContractBackend) (*AttestationHubEvents, error) {
	contract, err := bindAttestationHubEvents(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AttestationHubEvents{AttestationHubEventsCaller: AttestationHubEventsCaller{contract: contract}, AttestationHubEventsTransactor: AttestationHubEventsTransactor{contract: contract}, AttestationHubEventsFilterer: AttestationHubEventsFilterer{contract: contract}}, nil
}

// NewAttestationHubEventsCaller creates a new read-only instance of AttestationHubEvents, bound to a specific deployed contract.
func NewAttestationHubEventsCaller(address common.Address, caller bind.ContractCaller) (*AttestationHubEventsCaller, error) {
	contract, err := bindAttestationHubEvents(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AttestationHubEventsCaller{contract: contract}, nil
}

// NewAttestationHubEventsTransactor creates a new write-only instance of AttestationHubEvents, bound to a specific deployed contract.
func NewAttestationHubEventsTransactor(address common.Address, transactor bind.ContractTransactor) (*AttestationHubEventsTransactor, error) {
	contract, err := bindAttestationHubEvents(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AttestationHubEventsTransactor{contract: contract}, nil
}

// NewAttestationHubEventsFilterer creates a new log filterer instance of AttestationHubEvents, bound to a specific deployed contract.
func NewAttestationHubEventsFilterer(address common.Address, filterer bind.ContractFilterer) (*AttestationHubEventsFilterer, error) {
	contract, err := bindAttestationHubEvents(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AttestationHubEventsFilterer{contract: contract}, nil
}

// bindAttestationHubEvents binds a generic wrapper to an already deployed contract.
func bindAttestationHubEvents(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AttestationHubEventsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AttestationHubEvents *AttestationHubEventsRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AttestationHubEvents.Contract.AttestationHubEventsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AttestationHubEvents *AttestationHubEventsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AttestationHubEvents.Contract.AttestationHubEventsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AttestationHubEvents *AttestationHubEventsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AttestationHubEvents.Contract.AttestationHubEventsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AttestationHubEvents *AttestationHubEventsCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AttestationHubEvents.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AttestationHubEvents *AttestationHubEventsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AttestationHubEvents.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AttestationHubEvents *AttestationHubEventsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AttestationHubEvents.Contract.contract.Transact(opts, method, params...)
}

// AttestationHubEventsAttestationAcceptedIterator is returned from FilterAttestationAccepted and is used to iterate over the raw logs and unpacked data for AttestationAccepted events raised by the AttestationHubEvents contract.
type AttestationHubEventsAttestationAcceptedIterator struct {
	Event *AttestationHubEventsAttestationAccepted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *AttestationHubEventsAttestationAcceptedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(AttestationHubEventsAttestationAccepted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(AttestationHubEventsAttestationAccepted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *AttestationHubEventsAttestationAcceptedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *AttestationHubEventsAttestationAcceptedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// AttestationHubEventsAttestationAccepted represents a AttestationAccepted event raised by the AttestationHubEvents contract.
type AttestationHubEventsAttestationAccepted struct {
	Guards      []common.Address
	Notaries    []common.Address
	Attestation []byte
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterAttestationAccepted is a free log retrieval operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_AttestationHubEvents *AttestationHubEventsFilterer) FilterAttestationAccepted(opts *bind.FilterOpts) (*AttestationHubEventsAttestationAcceptedIterator, error) {

	logs, sub, err := _AttestationHubEvents.contract.FilterLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return &AttestationHubEventsAttestationAcceptedIterator{contract: _AttestationHubEvents.contract, event: "AttestationAccepted", logs: logs, sub: sub}, nil
}

// WatchAttestationAccepted is a free log subscription operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_AttestationHubEvents *AttestationHubEventsFilterer) WatchAttestationAccepted(opts *bind.WatchOpts, sink chan<- *AttestationHubEventsAttestationAccepted) (event.Subscription, error) {

	logs, sub, err := _AttestationHubEvents.contract.WatchLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(AttestationHubEventsAttestationAccepted)
				if err := _AttestationHubEvents.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAttestationAccepted is a log parse operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_AttestationHubEvents *AttestationHubEventsFilterer) ParseAttestationAccepted(log types.Log) (*AttestationHubEventsAttestationAccepted, error) {
	event := new(AttestationHubEventsAttestationAccepted)
	if err := _AttestationHubEvents.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// AuthMetaData contains all meta data concerning the Auth contract.
var AuthMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea2646970667358221220c7cd2274b1ab0875a3edf1bb441759e22d58c41b73d37a66c20dd62781965d0464736f6c63430008110033",
}

// AuthABI is the input ABI used to generate the binding from.
// Deprecated: Use AuthMetaData.ABI instead.
var AuthABI = AuthMetaData.ABI

// AuthBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use AuthMetaData.Bin instead.
var AuthBin = AuthMetaData.Bin

// DeployAuth deploys a new Ethereum contract, binding an instance of Auth to it.
func DeployAuth(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Auth, error) {
	parsed, err := AuthMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(AuthBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Auth{AuthCaller: AuthCaller{contract: contract}, AuthTransactor: AuthTransactor{contract: contract}, AuthFilterer: AuthFilterer{contract: contract}}, nil
}

// Auth is an auto generated Go binding around an Ethereum contract.
type Auth struct {
	AuthCaller     // Read-only binding to the contract
	AuthTransactor // Write-only binding to the contract
	AuthFilterer   // Log filterer for contract events
}

// AuthCaller is an auto generated read-only Go binding around an Ethereum contract.
type AuthCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AuthTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AuthTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AuthFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AuthFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AuthSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AuthSession struct {
	Contract     *Auth             // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AuthCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AuthCallerSession struct {
	Contract *AuthCaller   // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// AuthTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AuthTransactorSession struct {
	Contract     *AuthTransactor   // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AuthRaw is an auto generated low-level Go binding around an Ethereum contract.
type AuthRaw struct {
	Contract *Auth // Generic contract binding to access the raw methods on
}

// AuthCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AuthCallerRaw struct {
	Contract *AuthCaller // Generic read-only contract binding to access the raw methods on
}

// AuthTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AuthTransactorRaw struct {
	Contract *AuthTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAuth creates a new instance of Auth, bound to a specific deployed contract.
func NewAuth(address common.Address, backend bind.ContractBackend) (*Auth, error) {
	contract, err := bindAuth(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Auth{AuthCaller: AuthCaller{contract: contract}, AuthTransactor: AuthTransactor{contract: contract}, AuthFilterer: AuthFilterer{contract: contract}}, nil
}

// NewAuthCaller creates a new read-only instance of Auth, bound to a specific deployed contract.
func NewAuthCaller(address common.Address, caller bind.ContractCaller) (*AuthCaller, error) {
	contract, err := bindAuth(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AuthCaller{contract: contract}, nil
}

// NewAuthTransactor creates a new write-only instance of Auth, bound to a specific deployed contract.
func NewAuthTransactor(address common.Address, transactor bind.ContractTransactor) (*AuthTransactor, error) {
	contract, err := bindAuth(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AuthTransactor{contract: contract}, nil
}

// NewAuthFilterer creates a new log filterer instance of Auth, bound to a specific deployed contract.
func NewAuthFilterer(address common.Address, filterer bind.ContractFilterer) (*AuthFilterer, error) {
	contract, err := bindAuth(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AuthFilterer{contract: contract}, nil
}

// bindAuth binds a generic wrapper to an already deployed contract.
func bindAuth(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AuthABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Auth *AuthRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Auth.Contract.AuthCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Auth *AuthRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Auth.Contract.AuthTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Auth *AuthRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Auth.Contract.AuthTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Auth *AuthCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Auth.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Auth *AuthTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Auth.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Auth *AuthTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Auth.Contract.contract.Transact(opts, method, params...)
}

// ByteStringMetaData contains all meta data concerning the ByteString contract.
var ByteStringMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea26469706673582212209f0aefe5a3226c33896c9639b0b427b45c44d49831e15c92bac5ff6773efcd5b64736f6c63430008110033",
}

// ByteStringABI is the input ABI used to generate the binding from.
// Deprecated: Use ByteStringMetaData.ABI instead.
var ByteStringABI = ByteStringMetaData.ABI

// ByteStringBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ByteStringMetaData.Bin instead.
var ByteStringBin = ByteStringMetaData.Bin

// DeployByteString deploys a new Ethereum contract, binding an instance of ByteString to it.
func DeployByteString(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ByteString, error) {
	parsed, err := ByteStringMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ByteStringBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ByteString{ByteStringCaller: ByteStringCaller{contract: contract}, ByteStringTransactor: ByteStringTransactor{contract: contract}, ByteStringFilterer: ByteStringFilterer{contract: contract}}, nil
}

// ByteString is an auto generated Go binding around an Ethereum contract.
type ByteString struct {
	ByteStringCaller     // Read-only binding to the contract
	ByteStringTransactor // Write-only binding to the contract
	ByteStringFilterer   // Log filterer for contract events
}

// ByteStringCaller is an auto generated read-only Go binding around an Ethereum contract.
type ByteStringCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ByteStringTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ByteStringTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ByteStringFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ByteStringFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ByteStringSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ByteStringSession struct {
	Contract     *ByteString       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ByteStringCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ByteStringCallerSession struct {
	Contract *ByteStringCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// ByteStringTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ByteStringTransactorSession struct {
	Contract     *ByteStringTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// ByteStringRaw is an auto generated low-level Go binding around an Ethereum contract.
type ByteStringRaw struct {
	Contract *ByteString // Generic contract binding to access the raw methods on
}

// ByteStringCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ByteStringCallerRaw struct {
	Contract *ByteStringCaller // Generic read-only contract binding to access the raw methods on
}

// ByteStringTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ByteStringTransactorRaw struct {
	Contract *ByteStringTransactor // Generic write-only contract binding to access the raw methods on
}

// NewByteString creates a new instance of ByteString, bound to a specific deployed contract.
func NewByteString(address common.Address, backend bind.ContractBackend) (*ByteString, error) {
	contract, err := bindByteString(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ByteString{ByteStringCaller: ByteStringCaller{contract: contract}, ByteStringTransactor: ByteStringTransactor{contract: contract}, ByteStringFilterer: ByteStringFilterer{contract: contract}}, nil
}

// NewByteStringCaller creates a new read-only instance of ByteString, bound to a specific deployed contract.
func NewByteStringCaller(address common.Address, caller bind.ContractCaller) (*ByteStringCaller, error) {
	contract, err := bindByteString(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ByteStringCaller{contract: contract}, nil
}

// NewByteStringTransactor creates a new write-only instance of ByteString, bound to a specific deployed contract.
func NewByteStringTransactor(address common.Address, transactor bind.ContractTransactor) (*ByteStringTransactor, error) {
	contract, err := bindByteString(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ByteStringTransactor{contract: contract}, nil
}

// NewByteStringFilterer creates a new log filterer instance of ByteString, bound to a specific deployed contract.
func NewByteStringFilterer(address common.Address, filterer bind.ContractFilterer) (*ByteStringFilterer, error) {
	contract, err := bindByteString(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ByteStringFilterer{contract: contract}, nil
}

// bindByteString binds a generic wrapper to an already deployed contract.
func bindByteString(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ByteStringABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ByteString *ByteStringRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ByteString.Contract.ByteStringCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ByteString *ByteStringRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ByteString.Contract.ByteStringTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ByteString *ByteStringRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ByteString.Contract.ByteStringTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ByteString *ByteStringCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ByteString.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ByteString *ByteStringTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ByteString.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ByteString *ByteStringTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ByteString.Contract.contract.Transact(opts, method, params...)
}

// ContextUpgradeableMetaData contains all meta data concerning the ContextUpgradeable contract.
var ContextUpgradeableMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"}]",
}

// ContextUpgradeableABI is the input ABI used to generate the binding from.
// Deprecated: Use ContextUpgradeableMetaData.ABI instead.
var ContextUpgradeableABI = ContextUpgradeableMetaData.ABI

// ContextUpgradeable is an auto generated Go binding around an Ethereum contract.
type ContextUpgradeable struct {
	ContextUpgradeableCaller     // Read-only binding to the contract
	ContextUpgradeableTransactor // Write-only binding to the contract
	ContextUpgradeableFilterer   // Log filterer for contract events
}

// ContextUpgradeableCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContextUpgradeableCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContextUpgradeableTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContextUpgradeableTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContextUpgradeableFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContextUpgradeableFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContextUpgradeableSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContextUpgradeableSession struct {
	Contract     *ContextUpgradeable // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// ContextUpgradeableCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContextUpgradeableCallerSession struct {
	Contract *ContextUpgradeableCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// ContextUpgradeableTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContextUpgradeableTransactorSession struct {
	Contract     *ContextUpgradeableTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// ContextUpgradeableRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContextUpgradeableRaw struct {
	Contract *ContextUpgradeable // Generic contract binding to access the raw methods on
}

// ContextUpgradeableCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContextUpgradeableCallerRaw struct {
	Contract *ContextUpgradeableCaller // Generic read-only contract binding to access the raw methods on
}

// ContextUpgradeableTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContextUpgradeableTransactorRaw struct {
	Contract *ContextUpgradeableTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContextUpgradeable creates a new instance of ContextUpgradeable, bound to a specific deployed contract.
func NewContextUpgradeable(address common.Address, backend bind.ContractBackend) (*ContextUpgradeable, error) {
	contract, err := bindContextUpgradeable(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ContextUpgradeable{ContextUpgradeableCaller: ContextUpgradeableCaller{contract: contract}, ContextUpgradeableTransactor: ContextUpgradeableTransactor{contract: contract}, ContextUpgradeableFilterer: ContextUpgradeableFilterer{contract: contract}}, nil
}

// NewContextUpgradeableCaller creates a new read-only instance of ContextUpgradeable, bound to a specific deployed contract.
func NewContextUpgradeableCaller(address common.Address, caller bind.ContractCaller) (*ContextUpgradeableCaller, error) {
	contract, err := bindContextUpgradeable(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContextUpgradeableCaller{contract: contract}, nil
}

// NewContextUpgradeableTransactor creates a new write-only instance of ContextUpgradeable, bound to a specific deployed contract.
func NewContextUpgradeableTransactor(address common.Address, transactor bind.ContractTransactor) (*ContextUpgradeableTransactor, error) {
	contract, err := bindContextUpgradeable(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContextUpgradeableTransactor{contract: contract}, nil
}

// NewContextUpgradeableFilterer creates a new log filterer instance of ContextUpgradeable, bound to a specific deployed contract.
func NewContextUpgradeableFilterer(address common.Address, filterer bind.ContractFilterer) (*ContextUpgradeableFilterer, error) {
	contract, err := bindContextUpgradeable(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContextUpgradeableFilterer{contract: contract}, nil
}

// bindContextUpgradeable binds a generic wrapper to an already deployed contract.
func bindContextUpgradeable(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ContextUpgradeableABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContextUpgradeable *ContextUpgradeableRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContextUpgradeable.Contract.ContextUpgradeableCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContextUpgradeable *ContextUpgradeableRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContextUpgradeable.Contract.ContextUpgradeableTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContextUpgradeable *ContextUpgradeableRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContextUpgradeable.Contract.ContextUpgradeableTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ContextUpgradeable *ContextUpgradeableCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ContextUpgradeable.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ContextUpgradeable *ContextUpgradeableTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ContextUpgradeable.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ContextUpgradeable *ContextUpgradeableTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ContextUpgradeable.Contract.contract.Transact(opts, method, params...)
}

// ContextUpgradeableInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the ContextUpgradeable contract.
type ContextUpgradeableInitializedIterator struct {
	Event *ContextUpgradeableInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContextUpgradeableInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContextUpgradeableInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContextUpgradeableInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContextUpgradeableInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContextUpgradeableInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContextUpgradeableInitialized represents a Initialized event raised by the ContextUpgradeable contract.
type ContextUpgradeableInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_ContextUpgradeable *ContextUpgradeableFilterer) FilterInitialized(opts *bind.FilterOpts) (*ContextUpgradeableInitializedIterator, error) {

	logs, sub, err := _ContextUpgradeable.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &ContextUpgradeableInitializedIterator{contract: _ContextUpgradeable.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_ContextUpgradeable *ContextUpgradeableFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *ContextUpgradeableInitialized) (event.Subscription, error) {

	logs, sub, err := _ContextUpgradeable.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContextUpgradeableInitialized)
				if err := _ContextUpgradeable.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_ContextUpgradeable *ContextUpgradeableFilterer) ParseInitialized(log types.Log) (*ContextUpgradeableInitialized, error) {
	event := new(ContextUpgradeableInitialized)
	if err := _ContextUpgradeable.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationMetaData contains all meta data concerning the Destination contract.
var DestinationMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"guards\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"notaries\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"attestation\",\"type\":\"bytes\"}],\"name\":\"AttestationAccepted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"remoteDomain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"messageHash\",\"type\":\"bytes32\"}],\"name\":\"Executed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"notary\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"guard\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"reporter\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"report\",\"type\":\"bytes\"}],\"name\":\"NotaryBlacklisted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"remoteDomain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"previousConfirmAt\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newConfirmAt\",\"type\":\"uint256\"}],\"name\":\"SetConfirmation\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"SYNAPSE_DOMAIN\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_origin\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_optimisticSeconds\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"_root\",\"type\":\"bytes32\"}],\"name\":\"acceptableRoot\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"allAgents\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"allDomains\",\"outputs\":[{\"internalType\":\"uint32[]\",\"name\":\"domains_\",\"type\":\"uint32[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"amountAgents\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"amountDomains\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"blacklistedNotaries\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"guard\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"blacklistedAt\",\"type\":\"uint96\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_message\",\"type\":\"bytes\"},{\"internalType\":\"bytes32[32]\",\"name\":\"_proof\",\"type\":\"bytes32[32]\"},{\"internalType\":\"uint256\",\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"execute\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"uint256\",\"name\":\"_agentIndex\",\"type\":\"uint256\"}],\"name\":\"getAgent\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_domainIndex\",\"type\":\"uint256\"}],\"name\":\"getDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"isActiveDomain\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"localDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"messageStatus\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"mirrorRoots\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"notary\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"submittedAt\",\"type\":\"uint96\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"name\":\"mirrors\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"latestNonce\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"latestNotary\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_origin\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"_root\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"_confirmAt\",\"type\":\"uint256\"}],\"name\":\"setConfirmation\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"_systemRouter\",\"type\":\"address\"}],\"name\":\"setSystemRouter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo\",\"name\":\"_info\",\"type\":\"tuple\"}],\"name\":\"slashAgent\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_attestation\",\"type\":\"bytes\"}],\"name\":\"submitAttestation\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_report\",\"type\":\"bytes\"}],\"name\":\"submitReport\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_origin\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"_root\",\"type\":\"bytes32\"}],\"name\":\"submittedAt\",\"outputs\":[{\"internalType\":\"uint96\",\"name\":\"\",\"type\":\"uint96\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_requestID\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"_removeExisting\",\"type\":\"bool\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo[]\",\"name\":\"_infos\",\"type\":\"tuple[]\"}],\"name\":\"syncAgents\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"systemRouter\",\"outputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"versionString\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"bf61e67e": "SYNAPSE_DOMAIN()",
		"15a046aa": "acceptableRoot(uint32,uint32,bytes32)",
		"64ecb518": "allAgents(uint32)",
		"6f225878": "allDomains()",
		"32254098": "amountAgents(uint32)",
		"61b0b357": "amountDomains()",
		"3c3a2f87": "blacklistedNotaries(address)",
		"c1ab73df": "execute(bytes,bytes32[32],uint256)",
		"1d82873b": "getAgent(uint32,uint256)",
		"1a7a98e2": "getDomain(uint256)",
		"8129fc1c": "initialize()",
		"65e1e466": "isActiveAgent(address)",
		"0958117d": "isActiveAgent(uint32,address)",
		"4f5dbc0d": "isActiveDomain(uint32)",
		"8d3638f4": "localDomain()",
		"7952832b": "messageStatus(uint32,bytes32)",
		"79453331": "mirrorRoots(uint32,bytes32)",
		"6356267b": "mirrors(uint32)",
		"8da5cb5b": "owner()",
		"715018a6": "renounceOwnership()",
		"9df7d36d": "setConfirmation(uint32,bytes32,uint256)",
		"fbde22f7": "setSystemRouter(address)",
		"31f36451": "slashAgent(uint256,uint32,uint8,(uint32,address,bool))",
		"f646a512": "submitAttestation(bytes)",
		"5815869d": "submitReport(bytes)",
		"44792b83": "submittedAt(uint32,bytes32)",
		"cc118b4d": "syncAgents(uint256,uint32,uint8,uint256,bool,(uint32,address,bool)[])",
		"529d1549": "systemRouter()",
		"f2fde38b": "transferOwnership(address)",
		"54fd4d50": "version()",
	},
	Bin: "0x60e06040523480156200001157600080fd5b506040516200471f3803806200471f8339810160408190526200003491620000cf565b604080518082019091526005815264302e302e3160d81b60208083019190915263ffffffff8316608052815160a08190521115620000b85760405162461bcd60e51b815260206004820152601560248201527f537472696e67206c656e677468206f7665722033320000000000000000000000604482015260640160405180910390fd5b620000c381620000fe565b60c05250620001269050565b600060208284031215620000e257600080fd5b815163ffffffff81168114620000f757600080fd5b9392505050565b8051602080830151919081101562000120576000198160200360031b1b821691505b50919050565b60805160a05160c05161459f62000180600039600061041e015260006103fb0152600081816105cf0152818161076801528181610c27015281816111f20152818161205c01528181612f2201526130c3015261459f6000f3fe608060405234801561001057600080fd5b50600436106101da5760003560e01c806365e1e466116101045780638da5cb5b116100a2578063cc118b4d11610071578063cc118b4d14610640578063f2fde38b14610653578063f646a51214610666578063fbde22f71461067957600080fd5b80638da5cb5b146105f35780639df7d36d14610611578063bf61e67e14610624578063c1ab73df1461062d57600080fd5b806379453331116100de57806379453331146105315780637952832b1461059a5780638129fc1c146105c55780638d3638f4146105cd57600080fd5b806365e1e466146105015780636f22587814610514578063715018a61461052957600080fd5b806344792b831161017c5780635815869d1161014b5780635815869d1461044e57806361b0b357146104625780636356267b1461046a57806364ecb518146104e157600080fd5b806344792b83146103475780634f5dbc0d146103bd578063529d1549146103d057806354fd4d50146103f057600080fd5b80631d82873b116101b85780631d82873b1461024257806331f364511461027a578063322540981461028f5780633c3a2f87146102b057600080fd5b80630958117d146101df57806315a046aa146102075780631a7a98e21461021a575b600080fd5b6101f26101ed366004613d44565b61068c565b60405190151581526020015b60405180910390f35b6101f2610215366004613d7b565b6106a1565b61022d610228366004613db7565b61085a565b60405163ffffffff90911681526020016101fe565b610255610250366004613dd0565b610889565b60405173ffffffffffffffffffffffffffffffffffffffff90911681526020016101fe565b61028d610288366004613f08565b6108ba565b005b6102a261029d366004613f56565b6108fb565b6040519081526020016101fe565b61030e6102be366004613f71565b609d6020526000908152604090205473ffffffffffffffffffffffffffffffffffffffff8116907401000000000000000000000000000000000000000090046bffffffffffffffffffffffff1682565b6040805173ffffffffffffffffffffffffffffffffffffffff90931683526bffffffffffffffffffffffff9091166020830152016101fe565b6103a0610355366004613dd0565b63ffffffff91909116600090815260696020908152604080832093835292905220547401000000000000000000000000000000000000000090046bffffffffffffffffffffffff1690565b6040516bffffffffffffffffffffffff90911681526020016101fe565b6101f26103cb366004613f56565b61092a565b6068546102559073ffffffffffffffffffffffffffffffffffffffff1681565b6040805180820182527f000000000000000000000000000000000000000000000000000000000000000081527f0000000000000000000000000000000000000000000000000000000000000000602082015290516101fe9190613ff2565b6101f261045c366004614093565b50600090565b6102a2610935565b6104b0610478366004613f56565b606a6020526000908152604090205463ffffffff811690640100000000900473ffffffffffffffffffffffffffffffffffffffff1682565b6040805163ffffffff909316835273ffffffffffffffffffffffffffffffffffffffff9091166020830152016101fe565b6104f46104ef366004613f56565b61095f565b6040516101fe9190614119565b6101f261050f366004613f71565b61098e565b61051c610999565b6040516101fe919061412c565b61028d6109c0565b61030e61053f366004613dd0565b606960209081526000928352604080842090915290825290205473ffffffffffffffffffffffffffffffffffffffff8116907401000000000000000000000000000000000000000090046bffffffffffffffffffffffff1682565b6102a26105a8366004613dd0565b609c60209081526000928352604080842090915290825290205481565b61028d610a29565b7f000000000000000000000000000000000000000000000000000000000000000061022d565b60365473ffffffffffffffffffffffffffffffffffffffff16610255565b61028d61061f366004614176565b610add565b61022d6110ad81565b61028d61063b3660046141a9565b610bf2565b61028d61064e366004614209565b610eb9565b61028d610661366004613f71565b610f21565b6101f2610674366004614093565b61101a565b61028d610687366004613f71565b61104d565b600061069883836110fb565b90505b92915050565b63ffffffff83166000908152606960209081526040808320848452825280832081518083019092525473ffffffffffffffffffffffffffffffffffffffff811682527401000000000000000000000000000000000000000090046bffffffffffffffffffffffff169181018290529082036107635760405162461bcd60e51b815260206004820152600c60248201527f496e76616c696420726f6f74000000000000000000000000000000000000000060448201526064015b60405180910390fd5b61078e7f000000000000000000000000000000000000000000000000000000000000000082516110fb565b6107da5760405162461bcd60e51b815260206004820152600f60248201527f496e616374697665206e6f746172790000000000000000000000000000000000604482015260640161075a565b8363ffffffff1681602001516107f0919061432d565b6bffffffffffffffffffffffff1642101561084d5760405162461bcd60e51b815260206004820152601260248201527f216f7074696d69737469635365636f6e64730000000000000000000000000000604482015260640161075a565b60019150505b9392505050565b600061069b826001600061086d60005490565b815260200190815260200160002061112c90919063ffffffff16565b600061069883836002600061089d60005490565b81526020019081526020016000206111389092919063ffffffff16565b6108c2611189565b82826108cd826111f0565b6108e060025b60ff166001901b8261126b565b6108f2836000015184602001516112c5565b50505050505050565b600061069b826002600061090e60005490565b81526020019081526020016000206113c690919063ffffffff16565b600061069b826113df565b600061095a6001600061094760005490565b8152602001908152602001600020611414565b905090565b606061069b826002600061097260005490565b815260200190815260200160002061141e90919063ffffffff16565b600061069b8261149d565b6060600061069b600160006109ad60005490565b81526020019081526020016000206114cc565b60365473ffffffffffffffffffffffffffffffffffffffff163314610a275760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161075a565b565b6000610a3560016114d9565b90508015610a6a57600380547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff166101001790555b610a72611632565b6001609b558015610ada57600380547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00ff169055604051600181527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15b50565b60365473ffffffffffffffffffffffffffffffffffffffff163314610b445760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161075a565b63ffffffff8316600081815260696020908152604080832086845282529182902080546bffffffffffffffffffffffff8681167401000000000000000000000000000000000000000090810273ffffffffffffffffffffffffffffffffffffffff841617909355845192909104168082529181018590529092859290917f6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730910160405180910390a350505050565b6000610bfd846116b7565b90506000610c1062ffffff1983166116c8565b90506000610c2362ffffff198316611712565b90507f000000000000000000000000000000000000000000000000000000000000000063ffffffff16610c5b62ffffff19841661173e565b63ffffffff1614610cae5760405162461bcd60e51b815260206004820152600c60248201527f2164657374696e6174696f6e0000000000000000000000000000000000000000604482015260640161075a565b6000610cbf62ffffff19851661176a565b90506000610cde83838989610cd962ffffff198a166117b8565b6117e4565b90506001609b5414610d325760405162461bcd60e51b815260206004820152600a60248201527f217265656e7472616e7400000000000000000000000000000000000000000000604482015260640161075a565b6000609b55610d49610ada62ffffff198716611907565b63ffffffff83166000908152609c602090815260408083208584529091528120829055610d83610d7e62ffffff198716611966565b611992565b905073ffffffffffffffffffffffffffffffffffffffff811663e4d16d6285610db162ffffff1989166119d4565b610dc062ffffff198a16611a00565b63ffffffff891660009081526069602090815260408083208a84529091529020547401000000000000000000000000000000000000000090046bffffffffffffffffffffffff16610e24610e1962ffffff198e16611a2c565b62ffffff1916611a90565b6040518663ffffffff1660e01b8152600401610e44959493929190614381565b600060405180830381600087803b158015610e5e57600080fd5b505af1158015610e72573d6000803e3d6000fd5b505060405185925063ffffffff871691507f669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c90600090a350506001609b5550505050505050565b610ec1611189565b8484610ecc826111f0565b610ed660026108d3565b825160005b81811015610f1557610f05858281518110610ef857610ef86143c4565b6020026020010151611ae3565b610f0e816143f3565b9050610edb565b50505050505050505050565b60365473ffffffffffffffffffffffffffffffffffffffff163314610f885760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161075a565b73ffffffffffffffffffffffffffffffffffffffff81166110115760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201527f6464726573730000000000000000000000000000000000000000000000000000606482015260840161075a565b610ada81611b11565b60008061102683611b88565b905060008061103483611b99565b9150915061104482828588611daa565b95945050505050565b60365473ffffffffffffffffffffffffffffffffffffffff1633146110b45760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161075a565b606880547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff92909216919091179055565b600061069883836002600061110f60005490565b8152602001908152602001600020611f749092919063ffffffff16565b60006106988383612018565b63ffffffff8216600090815260208490526040812080548390811061115f5761115f6143c4565b60009182526020909120015473ffffffffffffffffffffffffffffffffffffffff16949350505050565b60685473ffffffffffffffffffffffffffffffffffffffff163314610a275760405162461bcd60e51b815260206004820152600d60248201527f2173797374656d526f7574657200000000000000000000000000000000000000604482015260640161075a565b7f000000000000000000000000000000000000000000000000000000000000000063ffffffff168163ffffffff1614610ada5760405162461bcd60e51b815260206004820152600c60248201527f216c6f63616c446f6d61696e0000000000000000000000000000000000000000604482015260640161075a565b6112758282612042565b6112c15760405162461bcd60e51b815260206004820152600e60248201527f21616c6c6f77656443616c6c6572000000000000000000000000000000000000604482015260640161075a565b5050565b60006112d18383612058565b156112de5750600061069b565b60008054808252600260205260409091206112fa90858561209e565b915081156113bf5760405173ffffffffffffffffffffffffffffffffffffffff84169063ffffffff8616907f36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e90600090a363ffffffff8416158015906113665750611364846108fb565b155b156113bf57600081815260016020526040902061138c9063ffffffff8087169061232616565b5060405163ffffffff8516907fa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a1990600090a25b5092915050565b63ffffffff166000908152602091909152604090205490565b600061069b8263ffffffff16600160006113f860005490565b815260200190815260200160002061233290919063ffffffff16565b600061069b825490565b63ffffffff81166000908152602083815260409182902080548351818402810184019094528084526060939283018282801561149057602002820191906000526020600020905b815473ffffffffffffffffffffffffffffffffffffffff168152600190910190602001808311611465575b5050505050905092915050565b600061069b82600260006114b060005490565b815260200190815260200160002061234a90919063ffffffff16565b606060006108538361239e565b600354600090610100900460ff1615611578578160ff1660011480156114fe5750303b155b6115705760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201527f647920696e697469616c697a6564000000000000000000000000000000000000606482015260840161075a565b506000919050565b60035460ff8084169116106115f55760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201527f647920696e697469616c697a6564000000000000000000000000000000000000606482015260840161075a565b50600380547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660ff92909216919091179055600190565b919050565b600354610100900460ff166116af5760405162461bcd60e51b815260206004820152602b60248201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960448201527f6e697469616c697a696e67000000000000000000000000000000000000000000606482015260840161075a565b610a276123fa565b600061069b82640301000000612480565b6000816116e062ffffff19821664030100000061249b565b506108536116f06003600261442b565b60ff166116fe85600161259b565b62ffffff19861691906403010100006125cd565b60008161172a62ffffff19821664030101000061249b565b5061085362ffffff19841660026004612642565b60008161175662ffffff19821664030101000061249b565b5061085362ffffff198416602a6004612642565b60008061177683612672565b6bffffffffffffffffffffffff16905060006117a08460181c6bffffffffffffffffffffffff1690565b6bffffffffffffffffffffffff169091209392505050565b6000816117d062ffffff19821664030101000061249b565b5061085362ffffff198416604e6004612642565b63ffffffff8086166000908152606a6020526040812054909116810361184c5760405162461bcd60e51b815260206004820152601160248201527f4d6972726f72206e6f7420616374697665000000000000000000000000000000604482015260640161075a565b63ffffffff86166000908152609c60209081526040808320888452909152902054156118ba5760405162461bcd60e51b815260206004820152601360248201527f214d6573736167655374617475732e4e6f6e6500000000000000000000000000604482015260640161075a565b6118ee8585602080602002604051908101604052809291908260208002808284376000920191909152508791506126999050565b90506118fb8683836106a1565b61104457611044614447565b60008161191f62ffffff19821664030100000061249b565b5061085361192e84600161259b565b61193a6003600261442b565b611947919060ff16614476565b61195285600261259b565b62ffffff19861691906403010200006125cd565b60008161197e62ffffff19821664030101000061249b565b5061085362ffffff198416602e602061273f565b60007401000000000000000000000000000000000000000082016119ce57505060685473ffffffffffffffffffffffffffffffffffffffff1690565b8161069b565b6000816119ec62ffffff19821664030101000061249b565b5061085362ffffff19841660266004612642565b600081611a1862ffffff19821664030101000061249b565b5061085362ffffff1984166006602061273f565b600081611a4462ffffff19821664030100000061249b565b50610853611a5384600261259b565b611a5e85600161259b565b611a6a6003600261442b565b611a77919060ff16614476565b611a819190614476565b62ffffff1985169060006128b9565b6060600080611aad8460181c6bffffffffffffffffffffffff1690565b6bffffffffffffffffffffffff1690506040519150819250611ad284836020016128f7565b508181016020016040529052919050565b806040015115611aff576112c181600001518260200151612a90565b6112c1816000015182602001516112c5565b6036805473ffffffffffffffffffffffffffffffffffffffff8381167fffffffffffffffffffffffff0000000000000000000000000000000000000000831681179093556040519116919082907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a35050565b600061069b82640101000000612480565b606080611bab62ffffff198416612b7e565b611bf75760405162461bcd60e51b815260206004820152601260248201527f4e6f7420616e206174746573746174696f6e0000000000000000000000000000604482015260640161075a565b6000611c10611c0b62ffffff198616612c14565b612c46565b9050600080611c2462ffffff198716612cad565b60ff16915060ff1691508167ffffffffffffffff811115611c4757611c47613e09565b604051908082528060200260200182016040528015611c70578160200160208202803683370190505b5094508067ffffffffffffffff811115611c8c57611c8c613e09565b604051908082528060200260200182016040528015611cb5578160200160208202803683370190505b50935060005b82811015611d2557611cde600085611cd962ffffff198b1685612cdb565b612d8c565b868281518110611cf057611cf06143c4565b73ffffffffffffffffffffffffffffffffffffffff90921660209283029190910190910152611d1e816143f3565b9050611cbb565b506000611d3762ffffff198816612df0565b905060005b82811015611da057611d598286611cd962ffffff198c1685612e1b565b868281518110611d6b57611d6b6143c4565b73ffffffffffffffffffffffffffffffffffffffff90921660209283029190910190910152611d99816143f3565b9050611d3c565b5050505050915091565b6000611dbb62ffffff198416612edc565b60ff16600003611e0d5760405162461bcd60e51b815260206004820152601360248201527f4e6f206775617264207369676e61747572657300000000000000000000000000604482015260640161075a565b611e1c62ffffff198416612efe565b60ff16600003611e6e5760405162461bcd60e51b815260206004820152601460248201527f4e6f206e6f74617279207369676e617475726573000000000000000000000000604482015260640161075a565b611e7783612f20565b6000611e8862ffffff198516613013565b905080611ed75760405162461bcd60e51b815260206004820152600a60248201527f456d70747920726f6f7400000000000000000000000000000000000000000000604482015260640161075a565b6000611ee862ffffff19861661303f565b90506000611efb62ffffff19871661306b565b9050600087600081518110611f1257611f126143c4565b60200260200101519050611f2881848487613097565b7f4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0898988604051611f5b93929190614489565b60405180910390a160019450505050505b949350505050565b73ffffffffffffffffffffffffffffffffffffffff81166000908152600184016020908152604080832081518083019092525463ffffffff8082168084526401000000009092047bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1693830193909352909185161480156110445750602001517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff161515949350505050565b600082600001828154811061202f5761202f6143c4565b9060005260206000200154905092915050565b600061204d82613233565b909216151592915050565b60007f000000000000000000000000000000000000000000000000000000000000000063ffffffff168363ffffffff16141580156106985750505063ffffffff16151590565b73ffffffffffffffffffffffffffffffffffffffff81166000908152600184016020908152604080832081518083019092525463ffffffff8116825264010000000090047bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1691810182905290158061212357508363ffffffff16816000015163ffffffff1614155b15612132576000915050610853565b60006001826020015161214591906144c2565b63ffffffff8616600090815260208890526040812080547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff9390931693509161218c906001906144f7565b90508281146122845760008282815481106121a9576121a96143c4565b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050808385815481106121e9576121e96143c4565b60009182526020808320909101805473ffffffffffffffffffffffffffffffffffffffff9485167fffffffffffffffffffffffff00000000000000000000000000000000000000009091161790558781015193909216815260018b019091526040902080547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff9092166401000000000263ffffffff9092169190911790555b818054806122945761229461450a565b6000828152602080822083017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff90810180547fffffffffffffffffffffffff000000000000000000000000000000000000000016905590920190925573ffffffffffffffffffffffffffffffffffffffff8816825260018a810190915260408220919091559450505050509392505050565b60006106988383613255565b60008181526001830160205260408120541515610698565b73ffffffffffffffffffffffffffffffffffffffff166000908152600191909101602052604090205464010000000090047bffffffffffffffffffffffffffffffffffffffffffffffffffffffff16151590565b6060816000018054806020026020016040519081016040528092919081815260200182805480156123ee57602002820191906000526020600020905b8154815260200190600101908083116123da575b50505050509050919050565b600354610100900460ff166124775760405162461bcd60e51b815260206004820152602b60248201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960448201527f6e697469616c697a696e67000000000000000000000000000000000000000000606482015260840161075a565b610a2733611b11565b81516000906020840161104464ffffffffff85168284613348565b60006124a7838361338d565b6125945760006124c56124b9856133af565b64ffffffffff166133d3565b91505060006124da8464ffffffffff166133d3565b6040517f5479706520617373657274696f6e206661696c65642e20476f7420307800000060208201527fffffffffffffffffffff0000000000000000000000000000000000000000000060b086811b8216603d8401527f2e20457870656374656420307800000000000000000000000000000000000000604784015283901b16605482015290925060009150605e0160405160208183030381529060405290508060405162461bcd60e51b815260040161075a9190613ff2565b5090919050565b600061069860028360038111156125b4576125b4614352565b6125be9190614539565b62ffffff198516906002612642565b6000806125d986612672565b6bffffffffffffffffffffffff1690506125f2866134bd565b846125fd8784614476565b6126079190614476565b111561261a5762ffffff19915050611f6c565b6126248582614476565b90506126388364ffffffffff168286613348565b9695505050505050565b600061264f826020614550565b61265a90600861442b565b60ff1661266885858561273f565b901c949350505050565b60008061268160606018614476565b9290921c6bffffffffffffffffffffffff1692915050565b8260005b602081101561273757600183821c1660008583602081106126c0576126c06143c4565b602002015190508160010361270057604080516020810183905290810185905260600160405160208183030381529060405280519060200120935061272d565b60408051602081018690529081018290526060016040516020818303038152906040528051906020012093505b505060010161269d565b509392505050565b60008160ff1660000361275457506000610853565b61276c8460181c6bffffffffffffffffffffffff1690565b6bffffffffffffffffffffffff1661278760ff841685614476565b11156127f0576127d761279985612672565b6bffffffffffffffffffffffff166127bf8660181c6bffffffffffffffffffffffff1690565b6bffffffffffffffffffffffff16858560ff166134f6565b60405162461bcd60e51b815260040161075a9190613ff2565b60208260ff1611156128445760405162461bcd60e51b815260206004820152601960248201527f496e6465783a206d6f7265207468616e20333220627974657300000000000000604482015260640161075a565b60088202600061285386612672565b6bffffffffffffffffffffffff16905060007f80000000000000000000000000000000000000000000000000000000000000007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff84011d91909501511695945050505050565b6000611f6c8484856128d98860181c6bffffffffffffffffffffffff1690565b6bffffffffffffffffffffffff166128f191906144f7565b856125cd565b600062ffffff198084160361294e5760405162461bcd60e51b815260206004820152601a60248201527f636f7079546f3a204e756c6c20706f696e746572206465726566000000000000604482015260640161075a565b61295783613686565b6129a35760405162461bcd60e51b815260206004820152601d60248201527f636f7079546f3a20496e76616c696420706f696e746572206465726566000000604482015260640161075a565b60006129bd8460181c6bffffffffffffffffffffffff1690565b6bffffffffffffffffffffffff16905060006129d885612672565b6bffffffffffffffffffffffff1690506000806040519150858211156129fe5760206060fd5b8386858560045afa905080612a555760405162461bcd60e51b815260206004820152601460248201527f6964656e746974793a206f7574206f6620676173000000000000000000000000604482015260640161075a565b612a85612a61886133af565b70ffffffffff000000000000000000000000606091821b168817901b851760181b90565b979650505050505050565b6000612a9c8383612058565b15612aa95750600061069b565b6000805480825260026020526040909120612ac59085856136c2565b915081156113bf5760405173ffffffffffffffffffffffffffffffffffffffff84169063ffffffff8616907ff317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d90600090a363ffffffff8416156113bf576000818152600160205260409020612b439063ffffffff808716906137e416565b156113bf5760405163ffffffff8516907f05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f122290600090a26113bf565b6000601882901c6bffffffffffffffffffffffff16612b9f602c6002614476565b811015612baf5750600092915050565b600080612bbb856137f0565b60ff91821693501690506000612bd18284614476565b905080600003612be75750600095945050505050565b612bf2604182614539565b612bfe602c6002614476565b612c089190614476565b90931495945050505050565b600081612c2c62ffffff19821664010100000061249b565b5061085362ffffff1984166000602c6401010100006125cd565b600061069b612c5a62ffffff19841661176a565b6040517f19457468657265756d205369676e6564204d6573736167653a0a3332000000006020820152603c8101829052600090605c01604051602081830303815290604052805190602001209050919050565b60008082612cc662ffffff19821664010100000061249b565b50612cd0846137f0565b909590945092505050565b600082612cf362ffffff19821664010100000061249b565b506000612cff856137f0565b5090508060ff168410612d545760405162461bcd60e51b815260206004820152600c60248201527f4f7574206f662072616e67650000000000000000000000000000000000000000604482015260640161075a565b611044612d62604186614539565b612d6e602c6002614476565b612d789190614476565b62ffffff19871690604163010000006125cd565b6000612d98838361381b565b9050612da484826110fb565b6108535760405162461bcd60e51b815260206004820152601860248201527f5369676e6572206973206e6f7420617574686f72697a65640000000000000000604482015260640161075a565b600081612e0862ffffff19821664010100000061249b565b5061085362ffffff198416600480612642565b600082612e3362ffffff19821664010100000061249b565b50600080612e40866137f0565b915091508060ff168510612e965760405162461bcd60e51b815260206004820152600c60248201527f4f7574206f662072616e67650000000000000000000000000000000000000000604482015260640161075a565b6126386041612ea860ff851688614476565b612eb29190614539565b612ebe602c6002614476565b612ec89190614476565b62ffffff19881690604163010000006125cd565b600081612ef462ffffff19821664010100000061249b565b50612737836137f0565b600081612f1662ffffff19821664010100000061249b565b50611f6c836137f0565b7f000000000000000000000000000000000000000000000000000000000000000063ffffffff8116612f5762ffffff19841661303f565b63ffffffff1603612faa5760405162461bcd60e51b815260206004820152601960248201527f216174746573746174696f6e4f726967696e3a206c6f63616c00000000000000604482015260640161075a565b63ffffffff8116612fc062ffffff198416612df0565b63ffffffff16146112c15760405162461bcd60e51b815260206004820152601f60248201527f216174746573746174696f6e44657374696e6174696f6e3a20216c6f63616c00604482015260640161075a565b60008161302b62ffffff19821664010100000061249b565b5061085362ffffff198416600c602061273f565b60008161305762ffffff19821664010100000061249b565b5061085362ffffff19841660006004612642565b60008161308362ffffff19821664010100000061249b565b5061085362ffffff19841660086004612642565b63ffffffff8084166000908152606a6020526040902080549091908116908416118061310957506131077f00000000000000000000000000000000000000000000000000000000000000008254640100000000900473ffffffffffffffffffffffffffffffffffffffff166110fb565b155b6131555760405162461bcd60e51b815260206004820152601460248201527f4f75746461746564206174746573746174696f6e000000000000000000000000604482015260640161075a565b80547fffffffffffffffff0000000000000000000000000000000000000000000000001664010000000073ffffffffffffffffffffffffffffffffffffffff9687169081027fffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000169190911763ffffffff94851617909155604080518082018252918252426bffffffffffffffffffffffff908116602080850191825296909516600090815260698752828120948152939095529091209051915191909316740100000000000000000000000000000000000000009190921602179055565b600081600281111561324757613247614352565b60ff166001901b9050919050565b6000818152600183016020526040812054801561333e5760006132796001836144f7565b855490915060009061328d906001906144f7565b90508181146132f25760008660000182815481106132ad576132ad6143c4565b90600052602060002001549050808760000184815481106132d0576132d06143c4565b6000918252602080832090910192909255918252600188019052604090208390555b85548690806133035761330361450a565b60019003818190600052602060002001600090559055856001016000868152602001908152602001600020600090556001935050505061069b565b600091505061069b565b6000806133558385614476565b9050604051811115613365575060005b8060000361337a5762ffffff19915050610853565b606085811b8517901b831760181b611044565b60008164ffffffffff166133a0846133af565b64ffffffffff16149392505050565b60008060606133bf816018614476565b6133c99190614476565b9290921c92915050565b600080601f5b600f8160ff1611156134465760006133f282600861442b565b60ff1685901c9050613403816138a4565b61ffff16841793508160ff1660101461341e57601084901b93505b507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff016133d9565b50600f5b60ff8160ff1610156134b757600061346382600861442b565b60ff1685901c9050613474816138a4565b61ffff16831792508160ff1660001461348f57601083901b92505b507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0161344a565b50915091565b60006134d78260181c6bffffffffffffffffffffffff1690565b6134e083612672565b016bffffffffffffffffffffffff169050919050565b60606000613503866133d3565b9150506000613511866133d3565b915050600061351f866133d3565b915050600061352d866133d3565b604080517f54797065644d656d566965772f696e646578202d204f76657272616e2074686560208201527f20766965772e20536c6963652069732061742030780000000000000000000000818301527fffffffffffff000000000000000000000000000000000000000000000000000060d098891b811660558301527f2077697468206c656e6774682030780000000000000000000000000000000000605b830181905297891b8116606a8301527f2e20417474656d7074656420746f20696e646578206174206f6666736574203060708301527f7800000000000000000000000000000000000000000000000000000000000000609083015295881b861660918201526097810196909652951b90921660a684015250507f2e0000000000000000000000000000000000000000000000000000000000000060ac8201528151808203608d01815260ad90910190915295945050505050565b6000613691826133af565b64ffffffffff1664ffffffffff036136ab57506000919050565b60006136b6836134bd565b60405110199392505050565b73ffffffffffffffffffffffffffffffffffffffff8116600090815260018401602052604081205464010000000090047bffffffffffffffffffffffffffffffffffffffffffffffffffffffff161561371d57506000610853565b5063ffffffff808316600081815260208681526040808320805460018181018355828652848620909101805473ffffffffffffffffffffffffffffffffffffffff8a167fffffffffffffffffffffffff000000000000000000000000000000000000000090911681179091558351808501855296875291547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff908116878601908152928652818b01909452919093209351925190911664010000000002919093161790559392505050565b600061069883836138d6565b6000808061380762ffffff198516602c6002612642565b60ff600882901c8116969116945092505050565b600060416bffffffffffffffffffffffff601884901c161461387f5760405162461bcd60e51b815260206004820152600f60248201527f4e6f742061207369676e61747572650000000000000000000000000000000000604482015260640161075a565b6000808061389262ffffff198616613925565b92509250925061263886828585613986565b60006138b660048360ff16901c6139ae565b60ff1661ffff919091161760081b6138cd826139ae565b60ff1617919050565b600081815260018301602052604081205461391d5750815460018181018455600084815260208082209093018490558454848252828601909352604090209190915561069b565b50600061069b565b6000808083630100000061393f62ffffff1983168261249b565b5061395362ffffff1987166000602061273f565b945061396762ffffff19871660208061273f565b935061397c62ffffff19871660406001612642565b9496939550505050565b600080600061399787878787613a0a565b915091506139a481613b22565b5095945050505050565b6040805180820190915260108082527f30313233343536373839616263646566000000000000000000000000000000006020830152600091600f841691829081106139fb576139fb6143c4565b016020015160f81c9392505050565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0831115613a415750600090506003613b19565b8460ff16601b14158015613a5957508460ff16601c14155b15613a6a5750600090506004613b19565b6040805160008082526020820180845289905260ff881692820192909252606081018690526080810185905260019060a0016020604051602081039080840390855afa158015613abe573d6000803e3d6000fd5b50506040517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0015191505073ffffffffffffffffffffffffffffffffffffffff8116613b1257600060019250925050613b19565b9150600090505b94509492505050565b6000816004811115613b3657613b36614352565b03613b3e5750565b6001816004811115613b5257613b52614352565b03613b9f5760405162461bcd60e51b815260206004820152601860248201527f45434453413a20696e76616c6964207369676e61747572650000000000000000604482015260640161075a565b6002816004811115613bb357613bb3614352565b03613c005760405162461bcd60e51b815260206004820152601f60248201527f45434453413a20696e76616c6964207369676e6174757265206c656e67746800604482015260640161075a565b6003816004811115613c1457613c14614352565b03613c875760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202773272076616c60448201527f7565000000000000000000000000000000000000000000000000000000000000606482015260840161075a565b6004816004811115613c9b57613c9b614352565b03610ada5760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202776272076616c60448201527f7565000000000000000000000000000000000000000000000000000000000000606482015260840161075a565b803563ffffffff8116811461162d57600080fd5b73ffffffffffffffffffffffffffffffffffffffff81168114610ada57600080fd5b60008060408385031215613d5757600080fd5b613d6083613d0e565b91506020830135613d7081613d22565b809150509250929050565b600080600060608486031215613d9057600080fd5b613d9984613d0e565b9250613da760208501613d0e565b9150604084013590509250925092565b600060208284031215613dc957600080fd5b5035919050565b60008060408385031215613de357600080fd5b613dec83613d0e565b946020939093013593505050565b80356003811061162d57600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b604051601f82017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe016810167ffffffffffffffff81118282101715613e7f57613e7f613e09565b604052919050565b8035801515811461162d57600080fd5b600060608284031215613ea957600080fd5b6040516060810181811067ffffffffffffffff82111715613ecc57613ecc613e09565b604052905080613edb83613d0e565b81526020830135613eeb81613d22565b6020820152613efc60408401613e87565b60408201525092915050565b60008060008060c08587031215613f1e57600080fd5b84359350613f2e60208601613d0e565b9250613f3c60408601613dfa565b9150613f4b8660608701613e97565b905092959194509250565b600060208284031215613f6857600080fd5b61069882613d0e565b600060208284031215613f8357600080fd5b813561085381613d22565b6000815180845260005b81811015613fb457602081850181015186830182015201613f98565b5060006020828601015260207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f83011685010191505092915050565b6020815260006106986020830184613f8e565b600082601f83011261401657600080fd5b813567ffffffffffffffff81111561403057614030613e09565b61406160207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f84011601613e38565b81815284602083860101111561407657600080fd5b816020850160208301376000918101602001919091529392505050565b6000602082840312156140a557600080fd5b813567ffffffffffffffff8111156140bc57600080fd5b611f6c84828501614005565b600081518084526020808501945080840160005b8381101561410e57815173ffffffffffffffffffffffffffffffffffffffff16875295820195908201906001016140dc565b509495945050505050565b60208152600061069860208301846140c8565b6020808252825182820181905260009190848201906040850190845b8181101561416a57835163ffffffff1683529284019291840191600101614148565b50909695505050505050565b60008060006060848603121561418b57600080fd5b61419484613d0e565b95602085013595506040909401359392505050565b600080600061044084860312156141bf57600080fd5b833567ffffffffffffffff8111156141d657600080fd5b6141e286828701614005565b9350506104208401858111156141f757600080fd5b60208501925080359150509250925092565b60008060008060008060c0878903121561422257600080fd5b863595506020614233818901613d0e565b955061424160408901613dfa565b9450606080890135945061425760808a01613e87565b935060a089013567ffffffffffffffff8082111561427457600080fd5b818b0191508b601f83011261428857600080fd5b81358181111561429a5761429a613e09565b6142a8858260051b01613e38565b818152858101925090840283018501908d8211156142c557600080fd5b928501925b818410156142eb576142dc8e85613e97565b835292840192918501916142ca565b8096505050505050509295509295509295565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6bffffffffffffffffffffffff8181168382160190808211156113bf576113bf6142fe565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b600063ffffffff80881683528087166020840152508460408301526bffffffffffffffffffffffff8416606083015260a06080830152612a8560a0830184613f8e565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203614424576144246142fe565b5060010190565b60ff81811683821602908116908181146113bf576113bf6142fe565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052600160045260246000fd5b8082018082111561069b5761069b6142fe565b60608152600061449c60608301866140c8565b82810360208401526144ae81866140c8565b905082810360408401526126388185613f8e565b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8281168282160390808211156113bf576113bf6142fe565b8181038181111561069b5761069b6142fe565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603160045260246000fd5b808202811582820484141761069b5761069b6142fe565b60ff828116828216039081111561069b5761069b6142fe56fea264697066735822122093060f7925c581bcd65e85477d827c4996439e48fd147ef964a928a3da1481b364736f6c63430008110033",
}

// DestinationABI is the input ABI used to generate the binding from.
// Deprecated: Use DestinationMetaData.ABI instead.
var DestinationABI = DestinationMetaData.ABI

// Deprecated: Use DestinationMetaData.Sigs instead.
// DestinationFuncSigs maps the 4-byte function signature to its string representation.
var DestinationFuncSigs = DestinationMetaData.Sigs

// DestinationBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use DestinationMetaData.Bin instead.
var DestinationBin = DestinationMetaData.Bin

// DeployDestination deploys a new Ethereum contract, binding an instance of Destination to it.
func DeployDestination(auth *bind.TransactOpts, backend bind.ContractBackend, _domain uint32) (common.Address, *types.Transaction, *Destination, error) {
	parsed, err := DestinationMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(DestinationBin), backend, _domain)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Destination{DestinationCaller: DestinationCaller{contract: contract}, DestinationTransactor: DestinationTransactor{contract: contract}, DestinationFilterer: DestinationFilterer{contract: contract}}, nil
}

// Destination is an auto generated Go binding around an Ethereum contract.
type Destination struct {
	DestinationCaller     // Read-only binding to the contract
	DestinationTransactor // Write-only binding to the contract
	DestinationFilterer   // Log filterer for contract events
}

// DestinationCaller is an auto generated read-only Go binding around an Ethereum contract.
type DestinationCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DestinationTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DestinationFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DestinationSession struct {
	Contract     *Destination      // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// DestinationCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DestinationCallerSession struct {
	Contract *DestinationCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts      // Call options to use throughout this session
}

// DestinationTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DestinationTransactorSession struct {
	Contract     *DestinationTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// DestinationRaw is an auto generated low-level Go binding around an Ethereum contract.
type DestinationRaw struct {
	Contract *Destination // Generic contract binding to access the raw methods on
}

// DestinationCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DestinationCallerRaw struct {
	Contract *DestinationCaller // Generic read-only contract binding to access the raw methods on
}

// DestinationTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DestinationTransactorRaw struct {
	Contract *DestinationTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDestination creates a new instance of Destination, bound to a specific deployed contract.
func NewDestination(address common.Address, backend bind.ContractBackend) (*Destination, error) {
	contract, err := bindDestination(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Destination{DestinationCaller: DestinationCaller{contract: contract}, DestinationTransactor: DestinationTransactor{contract: contract}, DestinationFilterer: DestinationFilterer{contract: contract}}, nil
}

// NewDestinationCaller creates a new read-only instance of Destination, bound to a specific deployed contract.
func NewDestinationCaller(address common.Address, caller bind.ContractCaller) (*DestinationCaller, error) {
	contract, err := bindDestination(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DestinationCaller{contract: contract}, nil
}

// NewDestinationTransactor creates a new write-only instance of Destination, bound to a specific deployed contract.
func NewDestinationTransactor(address common.Address, transactor bind.ContractTransactor) (*DestinationTransactor, error) {
	contract, err := bindDestination(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DestinationTransactor{contract: contract}, nil
}

// NewDestinationFilterer creates a new log filterer instance of Destination, bound to a specific deployed contract.
func NewDestinationFilterer(address common.Address, filterer bind.ContractFilterer) (*DestinationFilterer, error) {
	contract, err := bindDestination(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DestinationFilterer{contract: contract}, nil
}

// bindDestination binds a generic wrapper to an already deployed contract.
func bindDestination(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(DestinationABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Destination *DestinationRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Destination.Contract.DestinationCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Destination *DestinationRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Destination.Contract.DestinationTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Destination *DestinationRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Destination.Contract.DestinationTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Destination *DestinationCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Destination.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Destination *DestinationTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Destination.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Destination *DestinationTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Destination.Contract.contract.Transact(opts, method, params...)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_Destination *DestinationCaller) SYNAPSEDOMAIN(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "SYNAPSE_DOMAIN")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_Destination *DestinationSession) SYNAPSEDOMAIN() (uint32, error) {
	return _Destination.Contract.SYNAPSEDOMAIN(&_Destination.CallOpts)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_Destination *DestinationCallerSession) SYNAPSEDOMAIN() (uint32, error) {
	return _Destination.Contract.SYNAPSEDOMAIN(&_Destination.CallOpts)
}

// AcceptableRoot is a free data retrieval call binding the contract method 0x15a046aa.
//
// Solidity: function acceptableRoot(uint32 _origin, uint32 _optimisticSeconds, bytes32 _root) view returns(bool)
func (_Destination *DestinationCaller) AcceptableRoot(opts *bind.CallOpts, _origin uint32, _optimisticSeconds uint32, _root [32]byte) (bool, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "acceptableRoot", _origin, _optimisticSeconds, _root)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AcceptableRoot is a free data retrieval call binding the contract method 0x15a046aa.
//
// Solidity: function acceptableRoot(uint32 _origin, uint32 _optimisticSeconds, bytes32 _root) view returns(bool)
func (_Destination *DestinationSession) AcceptableRoot(_origin uint32, _optimisticSeconds uint32, _root [32]byte) (bool, error) {
	return _Destination.Contract.AcceptableRoot(&_Destination.CallOpts, _origin, _optimisticSeconds, _root)
}

// AcceptableRoot is a free data retrieval call binding the contract method 0x15a046aa.
//
// Solidity: function acceptableRoot(uint32 _origin, uint32 _optimisticSeconds, bytes32 _root) view returns(bool)
func (_Destination *DestinationCallerSession) AcceptableRoot(_origin uint32, _optimisticSeconds uint32, _root [32]byte) (bool, error) {
	return _Destination.Contract.AcceptableRoot(&_Destination.CallOpts, _origin, _optimisticSeconds, _root)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_Destination *DestinationCaller) AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "allAgents", _domain)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_Destination *DestinationSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _Destination.Contract.AllAgents(&_Destination.CallOpts, _domain)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_Destination *DestinationCallerSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _Destination.Contract.AllAgents(&_Destination.CallOpts, _domain)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_Destination *DestinationCaller) AllDomains(opts *bind.CallOpts) ([]uint32, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "allDomains")

	if err != nil {
		return *new([]uint32), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint32)).(*[]uint32)

	return out0, err

}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_Destination *DestinationSession) AllDomains() ([]uint32, error) {
	return _Destination.Contract.AllDomains(&_Destination.CallOpts)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_Destination *DestinationCallerSession) AllDomains() ([]uint32, error) {
	return _Destination.Contract.AllDomains(&_Destination.CallOpts)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_Destination *DestinationCaller) AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "amountAgents", _domain)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_Destination *DestinationSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _Destination.Contract.AmountAgents(&_Destination.CallOpts, _domain)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_Destination *DestinationCallerSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _Destination.Contract.AmountAgents(&_Destination.CallOpts, _domain)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_Destination *DestinationCaller) AmountDomains(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "amountDomains")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_Destination *DestinationSession) AmountDomains() (*big.Int, error) {
	return _Destination.Contract.AmountDomains(&_Destination.CallOpts)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_Destination *DestinationCallerSession) AmountDomains() (*big.Int, error) {
	return _Destination.Contract.AmountDomains(&_Destination.CallOpts)
}

// BlacklistedNotaries is a free data retrieval call binding the contract method 0x3c3a2f87.
//
// Solidity: function blacklistedNotaries(address ) view returns(address guard, uint96 blacklistedAt)
func (_Destination *DestinationCaller) BlacklistedNotaries(opts *bind.CallOpts, arg0 common.Address) (struct {
	Guard         common.Address
	BlacklistedAt *big.Int
}, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "blacklistedNotaries", arg0)

	outstruct := new(struct {
		Guard         common.Address
		BlacklistedAt *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Guard = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.BlacklistedAt = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// BlacklistedNotaries is a free data retrieval call binding the contract method 0x3c3a2f87.
//
// Solidity: function blacklistedNotaries(address ) view returns(address guard, uint96 blacklistedAt)
func (_Destination *DestinationSession) BlacklistedNotaries(arg0 common.Address) (struct {
	Guard         common.Address
	BlacklistedAt *big.Int
}, error) {
	return _Destination.Contract.BlacklistedNotaries(&_Destination.CallOpts, arg0)
}

// BlacklistedNotaries is a free data retrieval call binding the contract method 0x3c3a2f87.
//
// Solidity: function blacklistedNotaries(address ) view returns(address guard, uint96 blacklistedAt)
func (_Destination *DestinationCallerSession) BlacklistedNotaries(arg0 common.Address) (struct {
	Guard         common.Address
	BlacklistedAt *big.Int
}, error) {
	return _Destination.Contract.BlacklistedNotaries(&_Destination.CallOpts, arg0)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_Destination *DestinationCaller) GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "getAgent", _domain, _agentIndex)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_Destination *DestinationSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _Destination.Contract.GetAgent(&_Destination.CallOpts, _domain, _agentIndex)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_Destination *DestinationCallerSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _Destination.Contract.GetAgent(&_Destination.CallOpts, _domain, _agentIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_Destination *DestinationCaller) GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "getDomain", _domainIndex)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_Destination *DestinationSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _Destination.Contract.GetDomain(&_Destination.CallOpts, _domainIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_Destination *DestinationCallerSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _Destination.Contract.GetDomain(&_Destination.CallOpts, _domainIndex)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_Destination *DestinationCaller) IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "isActiveAgent", _domain, _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_Destination *DestinationSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _Destination.Contract.IsActiveAgent(&_Destination.CallOpts, _domain, _account)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_Destination *DestinationCallerSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _Destination.Contract.IsActiveAgent(&_Destination.CallOpts, _domain, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_Destination *DestinationCaller) IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "isActiveAgent0", _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_Destination *DestinationSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _Destination.Contract.IsActiveAgent0(&_Destination.CallOpts, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_Destination *DestinationCallerSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _Destination.Contract.IsActiveAgent0(&_Destination.CallOpts, _account)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_Destination *DestinationCaller) IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "isActiveDomain", _domain)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_Destination *DestinationSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _Destination.Contract.IsActiveDomain(&_Destination.CallOpts, _domain)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_Destination *DestinationCallerSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _Destination.Contract.IsActiveDomain(&_Destination.CallOpts, _domain)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_Destination *DestinationCaller) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "localDomain")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_Destination *DestinationSession) LocalDomain() (uint32, error) {
	return _Destination.Contract.LocalDomain(&_Destination.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_Destination *DestinationCallerSession) LocalDomain() (uint32, error) {
	return _Destination.Contract.LocalDomain(&_Destination.CallOpts)
}

// MessageStatus is a free data retrieval call binding the contract method 0x7952832b.
//
// Solidity: function messageStatus(uint32 , bytes32 ) view returns(bytes32)
func (_Destination *DestinationCaller) MessageStatus(opts *bind.CallOpts, arg0 uint32, arg1 [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "messageStatus", arg0, arg1)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// MessageStatus is a free data retrieval call binding the contract method 0x7952832b.
//
// Solidity: function messageStatus(uint32 , bytes32 ) view returns(bytes32)
func (_Destination *DestinationSession) MessageStatus(arg0 uint32, arg1 [32]byte) ([32]byte, error) {
	return _Destination.Contract.MessageStatus(&_Destination.CallOpts, arg0, arg1)
}

// MessageStatus is a free data retrieval call binding the contract method 0x7952832b.
//
// Solidity: function messageStatus(uint32 , bytes32 ) view returns(bytes32)
func (_Destination *DestinationCallerSession) MessageStatus(arg0 uint32, arg1 [32]byte) ([32]byte, error) {
	return _Destination.Contract.MessageStatus(&_Destination.CallOpts, arg0, arg1)
}

// MirrorRoots is a free data retrieval call binding the contract method 0x79453331.
//
// Solidity: function mirrorRoots(uint32 , bytes32 ) view returns(address notary, uint96 submittedAt)
func (_Destination *DestinationCaller) MirrorRoots(opts *bind.CallOpts, arg0 uint32, arg1 [32]byte) (struct {
	Notary      common.Address
	SubmittedAt *big.Int
}, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "mirrorRoots", arg0, arg1)

	outstruct := new(struct {
		Notary      common.Address
		SubmittedAt *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Notary = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.SubmittedAt = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// MirrorRoots is a free data retrieval call binding the contract method 0x79453331.
//
// Solidity: function mirrorRoots(uint32 , bytes32 ) view returns(address notary, uint96 submittedAt)
func (_Destination *DestinationSession) MirrorRoots(arg0 uint32, arg1 [32]byte) (struct {
	Notary      common.Address
	SubmittedAt *big.Int
}, error) {
	return _Destination.Contract.MirrorRoots(&_Destination.CallOpts, arg0, arg1)
}

// MirrorRoots is a free data retrieval call binding the contract method 0x79453331.
//
// Solidity: function mirrorRoots(uint32 , bytes32 ) view returns(address notary, uint96 submittedAt)
func (_Destination *DestinationCallerSession) MirrorRoots(arg0 uint32, arg1 [32]byte) (struct {
	Notary      common.Address
	SubmittedAt *big.Int
}, error) {
	return _Destination.Contract.MirrorRoots(&_Destination.CallOpts, arg0, arg1)
}

// Mirrors is a free data retrieval call binding the contract method 0x6356267b.
//
// Solidity: function mirrors(uint32 ) view returns(uint32 latestNonce, address latestNotary)
func (_Destination *DestinationCaller) Mirrors(opts *bind.CallOpts, arg0 uint32) (struct {
	LatestNonce  uint32
	LatestNotary common.Address
}, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "mirrors", arg0)

	outstruct := new(struct {
		LatestNonce  uint32
		LatestNotary common.Address
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.LatestNonce = *abi.ConvertType(out[0], new(uint32)).(*uint32)
	outstruct.LatestNotary = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)

	return *outstruct, err

}

// Mirrors is a free data retrieval call binding the contract method 0x6356267b.
//
// Solidity: function mirrors(uint32 ) view returns(uint32 latestNonce, address latestNotary)
func (_Destination *DestinationSession) Mirrors(arg0 uint32) (struct {
	LatestNonce  uint32
	LatestNotary common.Address
}, error) {
	return _Destination.Contract.Mirrors(&_Destination.CallOpts, arg0)
}

// Mirrors is a free data retrieval call binding the contract method 0x6356267b.
//
// Solidity: function mirrors(uint32 ) view returns(uint32 latestNonce, address latestNotary)
func (_Destination *DestinationCallerSession) Mirrors(arg0 uint32) (struct {
	LatestNonce  uint32
	LatestNotary common.Address
}, error) {
	return _Destination.Contract.Mirrors(&_Destination.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Destination *DestinationCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Destination *DestinationSession) Owner() (common.Address, error) {
	return _Destination.Contract.Owner(&_Destination.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Destination *DestinationCallerSession) Owner() (common.Address, error) {
	return _Destination.Contract.Owner(&_Destination.CallOpts)
}

// SubmittedAt is a free data retrieval call binding the contract method 0x44792b83.
//
// Solidity: function submittedAt(uint32 _origin, bytes32 _root) view returns(uint96)
func (_Destination *DestinationCaller) SubmittedAt(opts *bind.CallOpts, _origin uint32, _root [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "submittedAt", _origin, _root)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SubmittedAt is a free data retrieval call binding the contract method 0x44792b83.
//
// Solidity: function submittedAt(uint32 _origin, bytes32 _root) view returns(uint96)
func (_Destination *DestinationSession) SubmittedAt(_origin uint32, _root [32]byte) (*big.Int, error) {
	return _Destination.Contract.SubmittedAt(&_Destination.CallOpts, _origin, _root)
}

// SubmittedAt is a free data retrieval call binding the contract method 0x44792b83.
//
// Solidity: function submittedAt(uint32 _origin, bytes32 _root) view returns(uint96)
func (_Destination *DestinationCallerSession) SubmittedAt(_origin uint32, _root [32]byte) (*big.Int, error) {
	return _Destination.Contract.SubmittedAt(&_Destination.CallOpts, _origin, _root)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_Destination *DestinationCaller) SystemRouter(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "systemRouter")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_Destination *DestinationSession) SystemRouter() (common.Address, error) {
	return _Destination.Contract.SystemRouter(&_Destination.CallOpts)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_Destination *DestinationCallerSession) SystemRouter() (common.Address, error) {
	return _Destination.Contract.SystemRouter(&_Destination.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Destination *DestinationCaller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _Destination.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Destination *DestinationSession) Version() (string, error) {
	return _Destination.Contract.Version(&_Destination.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Destination *DestinationCallerSession) Version() (string, error) {
	return _Destination.Contract.Version(&_Destination.CallOpts)
}

// Execute is a paid mutator transaction binding the contract method 0xc1ab73df.
//
// Solidity: function execute(bytes _message, bytes32[32] _proof, uint256 _index) returns()
func (_Destination *DestinationTransactor) Execute(opts *bind.TransactOpts, _message []byte, _proof [32][32]byte, _index *big.Int) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "execute", _message, _proof, _index)
}

// Execute is a paid mutator transaction binding the contract method 0xc1ab73df.
//
// Solidity: function execute(bytes _message, bytes32[32] _proof, uint256 _index) returns()
func (_Destination *DestinationSession) Execute(_message []byte, _proof [32][32]byte, _index *big.Int) (*types.Transaction, error) {
	return _Destination.Contract.Execute(&_Destination.TransactOpts, _message, _proof, _index)
}

// Execute is a paid mutator transaction binding the contract method 0xc1ab73df.
//
// Solidity: function execute(bytes _message, bytes32[32] _proof, uint256 _index) returns()
func (_Destination *DestinationTransactorSession) Execute(_message []byte, _proof [32][32]byte, _index *big.Int) (*types.Transaction, error) {
	return _Destination.Contract.Execute(&_Destination.TransactOpts, _message, _proof, _index)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Destination *DestinationTransactor) Initialize(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "initialize")
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Destination *DestinationSession) Initialize() (*types.Transaction, error) {
	return _Destination.Contract.Initialize(&_Destination.TransactOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
//
// Solidity: function initialize() returns()
func (_Destination *DestinationTransactorSession) Initialize() (*types.Transaction, error) {
	return _Destination.Contract.Initialize(&_Destination.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Destination *DestinationTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Destination *DestinationSession) RenounceOwnership() (*types.Transaction, error) {
	return _Destination.Contract.RenounceOwnership(&_Destination.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Destination *DestinationTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _Destination.Contract.RenounceOwnership(&_Destination.TransactOpts)
}

// SetConfirmation is a paid mutator transaction binding the contract method 0x9df7d36d.
//
// Solidity: function setConfirmation(uint32 _origin, bytes32 _root, uint256 _confirmAt) returns()
func (_Destination *DestinationTransactor) SetConfirmation(opts *bind.TransactOpts, _origin uint32, _root [32]byte, _confirmAt *big.Int) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "setConfirmation", _origin, _root, _confirmAt)
}

// SetConfirmation is a paid mutator transaction binding the contract method 0x9df7d36d.
//
// Solidity: function setConfirmation(uint32 _origin, bytes32 _root, uint256 _confirmAt) returns()
func (_Destination *DestinationSession) SetConfirmation(_origin uint32, _root [32]byte, _confirmAt *big.Int) (*types.Transaction, error) {
	return _Destination.Contract.SetConfirmation(&_Destination.TransactOpts, _origin, _root, _confirmAt)
}

// SetConfirmation is a paid mutator transaction binding the contract method 0x9df7d36d.
//
// Solidity: function setConfirmation(uint32 _origin, bytes32 _root, uint256 _confirmAt) returns()
func (_Destination *DestinationTransactorSession) SetConfirmation(_origin uint32, _root [32]byte, _confirmAt *big.Int) (*types.Transaction, error) {
	return _Destination.Contract.SetConfirmation(&_Destination.TransactOpts, _origin, _root, _confirmAt)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_Destination *DestinationTransactor) SetSystemRouter(opts *bind.TransactOpts, _systemRouter common.Address) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "setSystemRouter", _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_Destination *DestinationSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _Destination.Contract.SetSystemRouter(&_Destination.TransactOpts, _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_Destination *DestinationTransactorSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _Destination.Contract.SetSystemRouter(&_Destination.TransactOpts, _systemRouter)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_Destination *DestinationTransactor) SlashAgent(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "slashAgent", arg0, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_Destination *DestinationSession) SlashAgent(arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _Destination.Contract.SlashAgent(&_Destination.TransactOpts, arg0, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_Destination *DestinationTransactorSession) SlashAgent(arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _Destination.Contract.SlashAgent(&_Destination.TransactOpts, arg0, _callOrigin, _caller, _info)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_Destination *DestinationTransactor) SubmitAttestation(opts *bind.TransactOpts, _attestation []byte) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "submitAttestation", _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_Destination *DestinationSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _Destination.Contract.SubmitAttestation(&_Destination.TransactOpts, _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_Destination *DestinationTransactorSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _Destination.Contract.SubmitAttestation(&_Destination.TransactOpts, _attestation)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_Destination *DestinationTransactor) SubmitReport(opts *bind.TransactOpts, _report []byte) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "submitReport", _report)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_Destination *DestinationSession) SubmitReport(_report []byte) (*types.Transaction, error) {
	return _Destination.Contract.SubmitReport(&_Destination.TransactOpts, _report)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_Destination *DestinationTransactorSession) SubmitReport(_report []byte) (*types.Transaction, error) {
	return _Destination.Contract.SubmitReport(&_Destination.TransactOpts, _report)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_Destination *DestinationTransactor) SyncAgents(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "syncAgents", arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_Destination *DestinationSession) SyncAgents(arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _Destination.Contract.SyncAgents(&_Destination.TransactOpts, arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_Destination *DestinationTransactorSession) SyncAgents(arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _Destination.Contract.SyncAgents(&_Destination.TransactOpts, arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Destination *DestinationTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Destination.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Destination *DestinationSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Destination.Contract.TransferOwnership(&_Destination.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Destination *DestinationTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Destination.Contract.TransferOwnership(&_Destination.TransactOpts, newOwner)
}

// DestinationAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the Destination contract.
type DestinationAgentAddedIterator struct {
	Event *DestinationAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationAgentAdded represents a AgentAdded event raised by the Destination contract.
type DestinationAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_Destination *DestinationFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*DestinationAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &DestinationAgentAddedIterator{contract: _Destination.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_Destination *DestinationFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *DestinationAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationAgentAdded)
				if err := _Destination.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_Destination *DestinationFilterer) ParseAgentAdded(log types.Log) (*DestinationAgentAdded, error) {
	event := new(DestinationAgentAdded)
	if err := _Destination.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the Destination contract.
type DestinationAgentRemovedIterator struct {
	Event *DestinationAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationAgentRemoved represents a AgentRemoved event raised by the Destination contract.
type DestinationAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_Destination *DestinationFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*DestinationAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &DestinationAgentRemovedIterator{contract: _Destination.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_Destination *DestinationFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *DestinationAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationAgentRemoved)
				if err := _Destination.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_Destination *DestinationFilterer) ParseAgentRemoved(log types.Log) (*DestinationAgentRemoved, error) {
	event := new(DestinationAgentRemoved)
	if err := _Destination.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationAttestationAcceptedIterator is returned from FilterAttestationAccepted and is used to iterate over the raw logs and unpacked data for AttestationAccepted events raised by the Destination contract.
type DestinationAttestationAcceptedIterator struct {
	Event *DestinationAttestationAccepted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationAttestationAcceptedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationAttestationAccepted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationAttestationAccepted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationAttestationAcceptedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationAttestationAcceptedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationAttestationAccepted represents a AttestationAccepted event raised by the Destination contract.
type DestinationAttestationAccepted struct {
	Guards      []common.Address
	Notaries    []common.Address
	Attestation []byte
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterAttestationAccepted is a free log retrieval operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_Destination *DestinationFilterer) FilterAttestationAccepted(opts *bind.FilterOpts) (*DestinationAttestationAcceptedIterator, error) {

	logs, sub, err := _Destination.contract.FilterLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return &DestinationAttestationAcceptedIterator{contract: _Destination.contract, event: "AttestationAccepted", logs: logs, sub: sub}, nil
}

// WatchAttestationAccepted is a free log subscription operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_Destination *DestinationFilterer) WatchAttestationAccepted(opts *bind.WatchOpts, sink chan<- *DestinationAttestationAccepted) (event.Subscription, error) {

	logs, sub, err := _Destination.contract.WatchLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationAttestationAccepted)
				if err := _Destination.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAttestationAccepted is a log parse operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_Destination *DestinationFilterer) ParseAttestationAccepted(log types.Log) (*DestinationAttestationAccepted, error) {
	event := new(DestinationAttestationAccepted)
	if err := _Destination.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the Destination contract.
type DestinationDomainActivatedIterator struct {
	Event *DestinationDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationDomainActivated represents a DomainActivated event raised by the Destination contract.
type DestinationDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_Destination *DestinationFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*DestinationDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &DestinationDomainActivatedIterator{contract: _Destination.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_Destination *DestinationFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *DestinationDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationDomainActivated)
				if err := _Destination.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_Destination *DestinationFilterer) ParseDomainActivated(log types.Log) (*DestinationDomainActivated, error) {
	event := new(DestinationDomainActivated)
	if err := _Destination.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the Destination contract.
type DestinationDomainDeactivatedIterator struct {
	Event *DestinationDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationDomainDeactivated represents a DomainDeactivated event raised by the Destination contract.
type DestinationDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_Destination *DestinationFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*DestinationDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &DestinationDomainDeactivatedIterator{contract: _Destination.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_Destination *DestinationFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *DestinationDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationDomainDeactivated)
				if err := _Destination.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_Destination *DestinationFilterer) ParseDomainDeactivated(log types.Log) (*DestinationDomainDeactivated, error) {
	event := new(DestinationDomainDeactivated)
	if err := _Destination.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationExecutedIterator is returned from FilterExecuted and is used to iterate over the raw logs and unpacked data for Executed events raised by the Destination contract.
type DestinationExecutedIterator struct {
	Event *DestinationExecuted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationExecuted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationExecuted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationExecuted represents a Executed event raised by the Destination contract.
type DestinationExecuted struct {
	RemoteDomain uint32
	MessageHash  [32]byte
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterExecuted is a free log retrieval operation binding the contract event 0x669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c.
//
// Solidity: event Executed(uint32 indexed remoteDomain, bytes32 indexed messageHash)
func (_Destination *DestinationFilterer) FilterExecuted(opts *bind.FilterOpts, remoteDomain []uint32, messageHash [][32]byte) (*DestinationExecutedIterator, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var messageHashRule []interface{}
	for _, messageHashItem := range messageHash {
		messageHashRule = append(messageHashRule, messageHashItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "Executed", remoteDomainRule, messageHashRule)
	if err != nil {
		return nil, err
	}
	return &DestinationExecutedIterator{contract: _Destination.contract, event: "Executed", logs: logs, sub: sub}, nil
}

// WatchExecuted is a free log subscription operation binding the contract event 0x669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c.
//
// Solidity: event Executed(uint32 indexed remoteDomain, bytes32 indexed messageHash)
func (_Destination *DestinationFilterer) WatchExecuted(opts *bind.WatchOpts, sink chan<- *DestinationExecuted, remoteDomain []uint32, messageHash [][32]byte) (event.Subscription, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var messageHashRule []interface{}
	for _, messageHashItem := range messageHash {
		messageHashRule = append(messageHashRule, messageHashItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "Executed", remoteDomainRule, messageHashRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationExecuted)
				if err := _Destination.contract.UnpackLog(event, "Executed", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExecuted is a log parse operation binding the contract event 0x669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c.
//
// Solidity: event Executed(uint32 indexed remoteDomain, bytes32 indexed messageHash)
func (_Destination *DestinationFilterer) ParseExecuted(log types.Log) (*DestinationExecuted, error) {
	event := new(DestinationExecuted)
	if err := _Destination.contract.UnpackLog(event, "Executed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the Destination contract.
type DestinationInitializedIterator struct {
	Event *DestinationInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationInitialized represents a Initialized event raised by the Destination contract.
type DestinationInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Destination *DestinationFilterer) FilterInitialized(opts *bind.FilterOpts) (*DestinationInitializedIterator, error) {

	logs, sub, err := _Destination.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &DestinationInitializedIterator{contract: _Destination.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Destination *DestinationFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *DestinationInitialized) (event.Subscription, error) {

	logs, sub, err := _Destination.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationInitialized)
				if err := _Destination.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Destination *DestinationFilterer) ParseInitialized(log types.Log) (*DestinationInitialized, error) {
	event := new(DestinationInitialized)
	if err := _Destination.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationNotaryBlacklistedIterator is returned from FilterNotaryBlacklisted and is used to iterate over the raw logs and unpacked data for NotaryBlacklisted events raised by the Destination contract.
type DestinationNotaryBlacklistedIterator struct {
	Event *DestinationNotaryBlacklisted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationNotaryBlacklistedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationNotaryBlacklisted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationNotaryBlacklisted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationNotaryBlacklistedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationNotaryBlacklistedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationNotaryBlacklisted represents a NotaryBlacklisted event raised by the Destination contract.
type DestinationNotaryBlacklisted struct {
	Notary   common.Address
	Guard    common.Address
	Reporter common.Address
	Report   []byte
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterNotaryBlacklisted is a free log retrieval operation binding the contract event 0x4d1427447a05b6ef418581d309b05433942b337215d6d762be7f30a4bf62cbb0.
//
// Solidity: event NotaryBlacklisted(address indexed notary, address indexed guard, address indexed reporter, bytes report)
func (_Destination *DestinationFilterer) FilterNotaryBlacklisted(opts *bind.FilterOpts, notary []common.Address, guard []common.Address, reporter []common.Address) (*DestinationNotaryBlacklistedIterator, error) {

	var notaryRule []interface{}
	for _, notaryItem := range notary {
		notaryRule = append(notaryRule, notaryItem)
	}
	var guardRule []interface{}
	for _, guardItem := range guard {
		guardRule = append(guardRule, guardItem)
	}
	var reporterRule []interface{}
	for _, reporterItem := range reporter {
		reporterRule = append(reporterRule, reporterItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "NotaryBlacklisted", notaryRule, guardRule, reporterRule)
	if err != nil {
		return nil, err
	}
	return &DestinationNotaryBlacklistedIterator{contract: _Destination.contract, event: "NotaryBlacklisted", logs: logs, sub: sub}, nil
}

// WatchNotaryBlacklisted is a free log subscription operation binding the contract event 0x4d1427447a05b6ef418581d309b05433942b337215d6d762be7f30a4bf62cbb0.
//
// Solidity: event NotaryBlacklisted(address indexed notary, address indexed guard, address indexed reporter, bytes report)
func (_Destination *DestinationFilterer) WatchNotaryBlacklisted(opts *bind.WatchOpts, sink chan<- *DestinationNotaryBlacklisted, notary []common.Address, guard []common.Address, reporter []common.Address) (event.Subscription, error) {

	var notaryRule []interface{}
	for _, notaryItem := range notary {
		notaryRule = append(notaryRule, notaryItem)
	}
	var guardRule []interface{}
	for _, guardItem := range guard {
		guardRule = append(guardRule, guardItem)
	}
	var reporterRule []interface{}
	for _, reporterItem := range reporter {
		reporterRule = append(reporterRule, reporterItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "NotaryBlacklisted", notaryRule, guardRule, reporterRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationNotaryBlacklisted)
				if err := _Destination.contract.UnpackLog(event, "NotaryBlacklisted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseNotaryBlacklisted is a log parse operation binding the contract event 0x4d1427447a05b6ef418581d309b05433942b337215d6d762be7f30a4bf62cbb0.
//
// Solidity: event NotaryBlacklisted(address indexed notary, address indexed guard, address indexed reporter, bytes report)
func (_Destination *DestinationFilterer) ParseNotaryBlacklisted(log types.Log) (*DestinationNotaryBlacklisted, error) {
	event := new(DestinationNotaryBlacklisted)
	if err := _Destination.contract.UnpackLog(event, "NotaryBlacklisted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the Destination contract.
type DestinationOwnershipTransferredIterator struct {
	Event *DestinationOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationOwnershipTransferred represents a OwnershipTransferred event raised by the Destination contract.
type DestinationOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Destination *DestinationFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*DestinationOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &DestinationOwnershipTransferredIterator{contract: _Destination.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Destination *DestinationFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *DestinationOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationOwnershipTransferred)
				if err := _Destination.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Destination *DestinationFilterer) ParseOwnershipTransferred(log types.Log) (*DestinationOwnershipTransferred, error) {
	event := new(DestinationOwnershipTransferred)
	if err := _Destination.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationSetConfirmationIterator is returned from FilterSetConfirmation and is used to iterate over the raw logs and unpacked data for SetConfirmation events raised by the Destination contract.
type DestinationSetConfirmationIterator struct {
	Event *DestinationSetConfirmation // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationSetConfirmationIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationSetConfirmation)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationSetConfirmation)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationSetConfirmationIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationSetConfirmationIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationSetConfirmation represents a SetConfirmation event raised by the Destination contract.
type DestinationSetConfirmation struct {
	RemoteDomain      uint32
	Root              [32]byte
	PreviousConfirmAt *big.Int
	NewConfirmAt      *big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterSetConfirmation is a free log retrieval operation binding the contract event 0x6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730.
//
// Solidity: event SetConfirmation(uint32 indexed remoteDomain, bytes32 indexed root, uint256 previousConfirmAt, uint256 newConfirmAt)
func (_Destination *DestinationFilterer) FilterSetConfirmation(opts *bind.FilterOpts, remoteDomain []uint32, root [][32]byte) (*DestinationSetConfirmationIterator, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var rootRule []interface{}
	for _, rootItem := range root {
		rootRule = append(rootRule, rootItem)
	}

	logs, sub, err := _Destination.contract.FilterLogs(opts, "SetConfirmation", remoteDomainRule, rootRule)
	if err != nil {
		return nil, err
	}
	return &DestinationSetConfirmationIterator{contract: _Destination.contract, event: "SetConfirmation", logs: logs, sub: sub}, nil
}

// WatchSetConfirmation is a free log subscription operation binding the contract event 0x6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730.
//
// Solidity: event SetConfirmation(uint32 indexed remoteDomain, bytes32 indexed root, uint256 previousConfirmAt, uint256 newConfirmAt)
func (_Destination *DestinationFilterer) WatchSetConfirmation(opts *bind.WatchOpts, sink chan<- *DestinationSetConfirmation, remoteDomain []uint32, root [][32]byte) (event.Subscription, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var rootRule []interface{}
	for _, rootItem := range root {
		rootRule = append(rootRule, rootItem)
	}

	logs, sub, err := _Destination.contract.WatchLogs(opts, "SetConfirmation", remoteDomainRule, rootRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationSetConfirmation)
				if err := _Destination.contract.UnpackLog(event, "SetConfirmation", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSetConfirmation is a log parse operation binding the contract event 0x6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730.
//
// Solidity: event SetConfirmation(uint32 indexed remoteDomain, bytes32 indexed root, uint256 previousConfirmAt, uint256 newConfirmAt)
func (_Destination *DestinationFilterer) ParseSetConfirmation(log types.Log) (*DestinationSetConfirmation, error) {
	event := new(DestinationSetConfirmation)
	if err := _Destination.contract.UnpackLog(event, "SetConfirmation", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationEventsMetaData contains all meta data concerning the DestinationEvents contract.
var DestinationEventsMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"remoteDomain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"messageHash\",\"type\":\"bytes32\"}],\"name\":\"Executed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"notary\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"guard\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"reporter\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"report\",\"type\":\"bytes\"}],\"name\":\"NotaryBlacklisted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"remoteDomain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"previousConfirmAt\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newConfirmAt\",\"type\":\"uint256\"}],\"name\":\"SetConfirmation\",\"type\":\"event\"}]",
}

// DestinationEventsABI is the input ABI used to generate the binding from.
// Deprecated: Use DestinationEventsMetaData.ABI instead.
var DestinationEventsABI = DestinationEventsMetaData.ABI

// DestinationEvents is an auto generated Go binding around an Ethereum contract.
type DestinationEvents struct {
	DestinationEventsCaller     // Read-only binding to the contract
	DestinationEventsTransactor // Write-only binding to the contract
	DestinationEventsFilterer   // Log filterer for contract events
}

// DestinationEventsCaller is an auto generated read-only Go binding around an Ethereum contract.
type DestinationEventsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationEventsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DestinationEventsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationEventsFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DestinationEventsFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationEventsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DestinationEventsSession struct {
	Contract     *DestinationEvents // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// DestinationEventsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DestinationEventsCallerSession struct {
	Contract *DestinationEventsCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// DestinationEventsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DestinationEventsTransactorSession struct {
	Contract     *DestinationEventsTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// DestinationEventsRaw is an auto generated low-level Go binding around an Ethereum contract.
type DestinationEventsRaw struct {
	Contract *DestinationEvents // Generic contract binding to access the raw methods on
}

// DestinationEventsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DestinationEventsCallerRaw struct {
	Contract *DestinationEventsCaller // Generic read-only contract binding to access the raw methods on
}

// DestinationEventsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DestinationEventsTransactorRaw struct {
	Contract *DestinationEventsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDestinationEvents creates a new instance of DestinationEvents, bound to a specific deployed contract.
func NewDestinationEvents(address common.Address, backend bind.ContractBackend) (*DestinationEvents, error) {
	contract, err := bindDestinationEvents(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &DestinationEvents{DestinationEventsCaller: DestinationEventsCaller{contract: contract}, DestinationEventsTransactor: DestinationEventsTransactor{contract: contract}, DestinationEventsFilterer: DestinationEventsFilterer{contract: contract}}, nil
}

// NewDestinationEventsCaller creates a new read-only instance of DestinationEvents, bound to a specific deployed contract.
func NewDestinationEventsCaller(address common.Address, caller bind.ContractCaller) (*DestinationEventsCaller, error) {
	contract, err := bindDestinationEvents(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DestinationEventsCaller{contract: contract}, nil
}

// NewDestinationEventsTransactor creates a new write-only instance of DestinationEvents, bound to a specific deployed contract.
func NewDestinationEventsTransactor(address common.Address, transactor bind.ContractTransactor) (*DestinationEventsTransactor, error) {
	contract, err := bindDestinationEvents(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DestinationEventsTransactor{contract: contract}, nil
}

// NewDestinationEventsFilterer creates a new log filterer instance of DestinationEvents, bound to a specific deployed contract.
func NewDestinationEventsFilterer(address common.Address, filterer bind.ContractFilterer) (*DestinationEventsFilterer, error) {
	contract, err := bindDestinationEvents(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DestinationEventsFilterer{contract: contract}, nil
}

// bindDestinationEvents binds a generic wrapper to an already deployed contract.
func bindDestinationEvents(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(DestinationEventsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DestinationEvents *DestinationEventsRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DestinationEvents.Contract.DestinationEventsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DestinationEvents *DestinationEventsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DestinationEvents.Contract.DestinationEventsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DestinationEvents *DestinationEventsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DestinationEvents.Contract.DestinationEventsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DestinationEvents *DestinationEventsCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DestinationEvents.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DestinationEvents *DestinationEventsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DestinationEvents.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DestinationEvents *DestinationEventsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DestinationEvents.Contract.contract.Transact(opts, method, params...)
}

// DestinationEventsExecutedIterator is returned from FilterExecuted and is used to iterate over the raw logs and unpacked data for Executed events raised by the DestinationEvents contract.
type DestinationEventsExecutedIterator struct {
	Event *DestinationEventsExecuted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationEventsExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationEventsExecuted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationEventsExecuted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationEventsExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationEventsExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationEventsExecuted represents a Executed event raised by the DestinationEvents contract.
type DestinationEventsExecuted struct {
	RemoteDomain uint32
	MessageHash  [32]byte
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterExecuted is a free log retrieval operation binding the contract event 0x669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c.
//
// Solidity: event Executed(uint32 indexed remoteDomain, bytes32 indexed messageHash)
func (_DestinationEvents *DestinationEventsFilterer) FilterExecuted(opts *bind.FilterOpts, remoteDomain []uint32, messageHash [][32]byte) (*DestinationEventsExecutedIterator, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var messageHashRule []interface{}
	for _, messageHashItem := range messageHash {
		messageHashRule = append(messageHashRule, messageHashItem)
	}

	logs, sub, err := _DestinationEvents.contract.FilterLogs(opts, "Executed", remoteDomainRule, messageHashRule)
	if err != nil {
		return nil, err
	}
	return &DestinationEventsExecutedIterator{contract: _DestinationEvents.contract, event: "Executed", logs: logs, sub: sub}, nil
}

// WatchExecuted is a free log subscription operation binding the contract event 0x669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c.
//
// Solidity: event Executed(uint32 indexed remoteDomain, bytes32 indexed messageHash)
func (_DestinationEvents *DestinationEventsFilterer) WatchExecuted(opts *bind.WatchOpts, sink chan<- *DestinationEventsExecuted, remoteDomain []uint32, messageHash [][32]byte) (event.Subscription, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var messageHashRule []interface{}
	for _, messageHashItem := range messageHash {
		messageHashRule = append(messageHashRule, messageHashItem)
	}

	logs, sub, err := _DestinationEvents.contract.WatchLogs(opts, "Executed", remoteDomainRule, messageHashRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationEventsExecuted)
				if err := _DestinationEvents.contract.UnpackLog(event, "Executed", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseExecuted is a log parse operation binding the contract event 0x669e7fdd8be1e7e702112740f1be69fecc3b3ffd7ecb0e6d830824d15f07a84c.
//
// Solidity: event Executed(uint32 indexed remoteDomain, bytes32 indexed messageHash)
func (_DestinationEvents *DestinationEventsFilterer) ParseExecuted(log types.Log) (*DestinationEventsExecuted, error) {
	event := new(DestinationEventsExecuted)
	if err := _DestinationEvents.contract.UnpackLog(event, "Executed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationEventsNotaryBlacklistedIterator is returned from FilterNotaryBlacklisted and is used to iterate over the raw logs and unpacked data for NotaryBlacklisted events raised by the DestinationEvents contract.
type DestinationEventsNotaryBlacklistedIterator struct {
	Event *DestinationEventsNotaryBlacklisted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationEventsNotaryBlacklistedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationEventsNotaryBlacklisted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationEventsNotaryBlacklisted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationEventsNotaryBlacklistedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationEventsNotaryBlacklistedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationEventsNotaryBlacklisted represents a NotaryBlacklisted event raised by the DestinationEvents contract.
type DestinationEventsNotaryBlacklisted struct {
	Notary   common.Address
	Guard    common.Address
	Reporter common.Address
	Report   []byte
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterNotaryBlacklisted is a free log retrieval operation binding the contract event 0x4d1427447a05b6ef418581d309b05433942b337215d6d762be7f30a4bf62cbb0.
//
// Solidity: event NotaryBlacklisted(address indexed notary, address indexed guard, address indexed reporter, bytes report)
func (_DestinationEvents *DestinationEventsFilterer) FilterNotaryBlacklisted(opts *bind.FilterOpts, notary []common.Address, guard []common.Address, reporter []common.Address) (*DestinationEventsNotaryBlacklistedIterator, error) {

	var notaryRule []interface{}
	for _, notaryItem := range notary {
		notaryRule = append(notaryRule, notaryItem)
	}
	var guardRule []interface{}
	for _, guardItem := range guard {
		guardRule = append(guardRule, guardItem)
	}
	var reporterRule []interface{}
	for _, reporterItem := range reporter {
		reporterRule = append(reporterRule, reporterItem)
	}

	logs, sub, err := _DestinationEvents.contract.FilterLogs(opts, "NotaryBlacklisted", notaryRule, guardRule, reporterRule)
	if err != nil {
		return nil, err
	}
	return &DestinationEventsNotaryBlacklistedIterator{contract: _DestinationEvents.contract, event: "NotaryBlacklisted", logs: logs, sub: sub}, nil
}

// WatchNotaryBlacklisted is a free log subscription operation binding the contract event 0x4d1427447a05b6ef418581d309b05433942b337215d6d762be7f30a4bf62cbb0.
//
// Solidity: event NotaryBlacklisted(address indexed notary, address indexed guard, address indexed reporter, bytes report)
func (_DestinationEvents *DestinationEventsFilterer) WatchNotaryBlacklisted(opts *bind.WatchOpts, sink chan<- *DestinationEventsNotaryBlacklisted, notary []common.Address, guard []common.Address, reporter []common.Address) (event.Subscription, error) {

	var notaryRule []interface{}
	for _, notaryItem := range notary {
		notaryRule = append(notaryRule, notaryItem)
	}
	var guardRule []interface{}
	for _, guardItem := range guard {
		guardRule = append(guardRule, guardItem)
	}
	var reporterRule []interface{}
	for _, reporterItem := range reporter {
		reporterRule = append(reporterRule, reporterItem)
	}

	logs, sub, err := _DestinationEvents.contract.WatchLogs(opts, "NotaryBlacklisted", notaryRule, guardRule, reporterRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationEventsNotaryBlacklisted)
				if err := _DestinationEvents.contract.UnpackLog(event, "NotaryBlacklisted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseNotaryBlacklisted is a log parse operation binding the contract event 0x4d1427447a05b6ef418581d309b05433942b337215d6d762be7f30a4bf62cbb0.
//
// Solidity: event NotaryBlacklisted(address indexed notary, address indexed guard, address indexed reporter, bytes report)
func (_DestinationEvents *DestinationEventsFilterer) ParseNotaryBlacklisted(log types.Log) (*DestinationEventsNotaryBlacklisted, error) {
	event := new(DestinationEventsNotaryBlacklisted)
	if err := _DestinationEvents.contract.UnpackLog(event, "NotaryBlacklisted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationEventsSetConfirmationIterator is returned from FilterSetConfirmation and is used to iterate over the raw logs and unpacked data for SetConfirmation events raised by the DestinationEvents contract.
type DestinationEventsSetConfirmationIterator struct {
	Event *DestinationEventsSetConfirmation // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationEventsSetConfirmationIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationEventsSetConfirmation)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationEventsSetConfirmation)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationEventsSetConfirmationIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationEventsSetConfirmationIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationEventsSetConfirmation represents a SetConfirmation event raised by the DestinationEvents contract.
type DestinationEventsSetConfirmation struct {
	RemoteDomain      uint32
	Root              [32]byte
	PreviousConfirmAt *big.Int
	NewConfirmAt      *big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterSetConfirmation is a free log retrieval operation binding the contract event 0x6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730.
//
// Solidity: event SetConfirmation(uint32 indexed remoteDomain, bytes32 indexed root, uint256 previousConfirmAt, uint256 newConfirmAt)
func (_DestinationEvents *DestinationEventsFilterer) FilterSetConfirmation(opts *bind.FilterOpts, remoteDomain []uint32, root [][32]byte) (*DestinationEventsSetConfirmationIterator, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var rootRule []interface{}
	for _, rootItem := range root {
		rootRule = append(rootRule, rootItem)
	}

	logs, sub, err := _DestinationEvents.contract.FilterLogs(opts, "SetConfirmation", remoteDomainRule, rootRule)
	if err != nil {
		return nil, err
	}
	return &DestinationEventsSetConfirmationIterator{contract: _DestinationEvents.contract, event: "SetConfirmation", logs: logs, sub: sub}, nil
}

// WatchSetConfirmation is a free log subscription operation binding the contract event 0x6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730.
//
// Solidity: event SetConfirmation(uint32 indexed remoteDomain, bytes32 indexed root, uint256 previousConfirmAt, uint256 newConfirmAt)
func (_DestinationEvents *DestinationEventsFilterer) WatchSetConfirmation(opts *bind.WatchOpts, sink chan<- *DestinationEventsSetConfirmation, remoteDomain []uint32, root [][32]byte) (event.Subscription, error) {

	var remoteDomainRule []interface{}
	for _, remoteDomainItem := range remoteDomain {
		remoteDomainRule = append(remoteDomainRule, remoteDomainItem)
	}
	var rootRule []interface{}
	for _, rootItem := range root {
		rootRule = append(rootRule, rootItem)
	}

	logs, sub, err := _DestinationEvents.contract.WatchLogs(opts, "SetConfirmation", remoteDomainRule, rootRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationEventsSetConfirmation)
				if err := _DestinationEvents.contract.UnpackLog(event, "SetConfirmation", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSetConfirmation is a log parse operation binding the contract event 0x6dc81ebe3eada4cb187322470457db45b05b451f739729cfa5789316e9722730.
//
// Solidity: event SetConfirmation(uint32 indexed remoteDomain, bytes32 indexed root, uint256 previousConfirmAt, uint256 newConfirmAt)
func (_DestinationEvents *DestinationEventsFilterer) ParseSetConfirmation(log types.Log) (*DestinationEventsSetConfirmation, error) {
	event := new(DestinationEventsSetConfirmation)
	if err := _DestinationEvents.contract.UnpackLog(event, "SetConfirmation", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubMetaData contains all meta data concerning the DestinationHub contract.
var DestinationHubMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"guards\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"notaries\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"attestation\",\"type\":\"bytes\"}],\"name\":\"AttestationAccepted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"SYNAPSE_DOMAIN\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_origin\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_optimisticSeconds\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"_root\",\"type\":\"bytes32\"}],\"name\":\"acceptableRoot\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"allAgents\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"allDomains\",\"outputs\":[{\"internalType\":\"uint32[]\",\"name\":\"domains_\",\"type\":\"uint32[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"amountAgents\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"amountDomains\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"uint256\",\"name\":\"_agentIndex\",\"type\":\"uint256\"}],\"name\":\"getAgent\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_domainIndex\",\"type\":\"uint256\"}],\"name\":\"getDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"isActiveDomain\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"localDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"mirrorRoots\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"notary\",\"type\":\"address\"},{\"internalType\":\"uint96\",\"name\":\"submittedAt\",\"type\":\"uint96\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"name\":\"mirrors\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"latestNonce\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"latestNotary\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"_systemRouter\",\"type\":\"address\"}],\"name\":\"setSystemRouter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo\",\"name\":\"_info\",\"type\":\"tuple\"}],\"name\":\"slashAgent\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_attestation\",\"type\":\"bytes\"}],\"name\":\"submitAttestation\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_report\",\"type\":\"bytes\"}],\"name\":\"submitReport\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_origin\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"_root\",\"type\":\"bytes32\"}],\"name\":\"submittedAt\",\"outputs\":[{\"internalType\":\"uint96\",\"name\":\"\",\"type\":\"uint96\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_requestID\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"_removeExisting\",\"type\":\"bool\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo[]\",\"name\":\"_infos\",\"type\":\"tuple[]\"}],\"name\":\"syncAgents\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"systemRouter\",\"outputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"bf61e67e": "SYNAPSE_DOMAIN()",
		"15a046aa": "acceptableRoot(uint32,uint32,bytes32)",
		"64ecb518": "allAgents(uint32)",
		"6f225878": "allDomains()",
		"32254098": "amountAgents(uint32)",
		"61b0b357": "amountDomains()",
		"1d82873b": "getAgent(uint32,uint256)",
		"1a7a98e2": "getDomain(uint256)",
		"65e1e466": "isActiveAgent(address)",
		"0958117d": "isActiveAgent(uint32,address)",
		"4f5dbc0d": "isActiveDomain(uint32)",
		"8d3638f4": "localDomain()",
		"79453331": "mirrorRoots(uint32,bytes32)",
		"6356267b": "mirrors(uint32)",
		"8da5cb5b": "owner()",
		"715018a6": "renounceOwnership()",
		"fbde22f7": "setSystemRouter(address)",
		"31f36451": "slashAgent(uint256,uint32,uint8,(uint32,address,bool))",
		"f646a512": "submitAttestation(bytes)",
		"5815869d": "submitReport(bytes)",
		"44792b83": "submittedAt(uint32,bytes32)",
		"cc118b4d": "syncAgents(uint256,uint32,uint8,uint256,bool,(uint32,address,bool)[])",
		"529d1549": "systemRouter()",
		"f2fde38b": "transferOwnership(address)",
	},
}

// DestinationHubABI is the input ABI used to generate the binding from.
// Deprecated: Use DestinationHubMetaData.ABI instead.
var DestinationHubABI = DestinationHubMetaData.ABI

// Deprecated: Use DestinationHubMetaData.Sigs instead.
// DestinationHubFuncSigs maps the 4-byte function signature to its string representation.
var DestinationHubFuncSigs = DestinationHubMetaData.Sigs

// DestinationHub is an auto generated Go binding around an Ethereum contract.
type DestinationHub struct {
	DestinationHubCaller     // Read-only binding to the contract
	DestinationHubTransactor // Write-only binding to the contract
	DestinationHubFilterer   // Log filterer for contract events
}

// DestinationHubCaller is an auto generated read-only Go binding around an Ethereum contract.
type DestinationHubCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationHubTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DestinationHubTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationHubFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DestinationHubFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DestinationHubSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DestinationHubSession struct {
	Contract     *DestinationHub   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// DestinationHubCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DestinationHubCallerSession struct {
	Contract *DestinationHubCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// DestinationHubTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DestinationHubTransactorSession struct {
	Contract     *DestinationHubTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// DestinationHubRaw is an auto generated low-level Go binding around an Ethereum contract.
type DestinationHubRaw struct {
	Contract *DestinationHub // Generic contract binding to access the raw methods on
}

// DestinationHubCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DestinationHubCallerRaw struct {
	Contract *DestinationHubCaller // Generic read-only contract binding to access the raw methods on
}

// DestinationHubTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DestinationHubTransactorRaw struct {
	Contract *DestinationHubTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDestinationHub creates a new instance of DestinationHub, bound to a specific deployed contract.
func NewDestinationHub(address common.Address, backend bind.ContractBackend) (*DestinationHub, error) {
	contract, err := bindDestinationHub(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &DestinationHub{DestinationHubCaller: DestinationHubCaller{contract: contract}, DestinationHubTransactor: DestinationHubTransactor{contract: contract}, DestinationHubFilterer: DestinationHubFilterer{contract: contract}}, nil
}

// NewDestinationHubCaller creates a new read-only instance of DestinationHub, bound to a specific deployed contract.
func NewDestinationHubCaller(address common.Address, caller bind.ContractCaller) (*DestinationHubCaller, error) {
	contract, err := bindDestinationHub(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DestinationHubCaller{contract: contract}, nil
}

// NewDestinationHubTransactor creates a new write-only instance of DestinationHub, bound to a specific deployed contract.
func NewDestinationHubTransactor(address common.Address, transactor bind.ContractTransactor) (*DestinationHubTransactor, error) {
	contract, err := bindDestinationHub(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DestinationHubTransactor{contract: contract}, nil
}

// NewDestinationHubFilterer creates a new log filterer instance of DestinationHub, bound to a specific deployed contract.
func NewDestinationHubFilterer(address common.Address, filterer bind.ContractFilterer) (*DestinationHubFilterer, error) {
	contract, err := bindDestinationHub(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DestinationHubFilterer{contract: contract}, nil
}

// bindDestinationHub binds a generic wrapper to an already deployed contract.
func bindDestinationHub(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(DestinationHubABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DestinationHub *DestinationHubRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DestinationHub.Contract.DestinationHubCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DestinationHub *DestinationHubRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DestinationHub.Contract.DestinationHubTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DestinationHub *DestinationHubRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DestinationHub.Contract.DestinationHubTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DestinationHub *DestinationHubCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DestinationHub.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DestinationHub *DestinationHubTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DestinationHub.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DestinationHub *DestinationHubTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DestinationHub.Contract.contract.Transact(opts, method, params...)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_DestinationHub *DestinationHubCaller) SYNAPSEDOMAIN(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "SYNAPSE_DOMAIN")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_DestinationHub *DestinationHubSession) SYNAPSEDOMAIN() (uint32, error) {
	return _DestinationHub.Contract.SYNAPSEDOMAIN(&_DestinationHub.CallOpts)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_DestinationHub *DestinationHubCallerSession) SYNAPSEDOMAIN() (uint32, error) {
	return _DestinationHub.Contract.SYNAPSEDOMAIN(&_DestinationHub.CallOpts)
}

// AcceptableRoot is a free data retrieval call binding the contract method 0x15a046aa.
//
// Solidity: function acceptableRoot(uint32 _origin, uint32 _optimisticSeconds, bytes32 _root) view returns(bool)
func (_DestinationHub *DestinationHubCaller) AcceptableRoot(opts *bind.CallOpts, _origin uint32, _optimisticSeconds uint32, _root [32]byte) (bool, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "acceptableRoot", _origin, _optimisticSeconds, _root)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AcceptableRoot is a free data retrieval call binding the contract method 0x15a046aa.
//
// Solidity: function acceptableRoot(uint32 _origin, uint32 _optimisticSeconds, bytes32 _root) view returns(bool)
func (_DestinationHub *DestinationHubSession) AcceptableRoot(_origin uint32, _optimisticSeconds uint32, _root [32]byte) (bool, error) {
	return _DestinationHub.Contract.AcceptableRoot(&_DestinationHub.CallOpts, _origin, _optimisticSeconds, _root)
}

// AcceptableRoot is a free data retrieval call binding the contract method 0x15a046aa.
//
// Solidity: function acceptableRoot(uint32 _origin, uint32 _optimisticSeconds, bytes32 _root) view returns(bool)
func (_DestinationHub *DestinationHubCallerSession) AcceptableRoot(_origin uint32, _optimisticSeconds uint32, _root [32]byte) (bool, error) {
	return _DestinationHub.Contract.AcceptableRoot(&_DestinationHub.CallOpts, _origin, _optimisticSeconds, _root)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_DestinationHub *DestinationHubCaller) AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "allAgents", _domain)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_DestinationHub *DestinationHubSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _DestinationHub.Contract.AllAgents(&_DestinationHub.CallOpts, _domain)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_DestinationHub *DestinationHubCallerSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _DestinationHub.Contract.AllAgents(&_DestinationHub.CallOpts, _domain)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_DestinationHub *DestinationHubCaller) AllDomains(opts *bind.CallOpts) ([]uint32, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "allDomains")

	if err != nil {
		return *new([]uint32), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint32)).(*[]uint32)

	return out0, err

}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_DestinationHub *DestinationHubSession) AllDomains() ([]uint32, error) {
	return _DestinationHub.Contract.AllDomains(&_DestinationHub.CallOpts)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_DestinationHub *DestinationHubCallerSession) AllDomains() ([]uint32, error) {
	return _DestinationHub.Contract.AllDomains(&_DestinationHub.CallOpts)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_DestinationHub *DestinationHubCaller) AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "amountAgents", _domain)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_DestinationHub *DestinationHubSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _DestinationHub.Contract.AmountAgents(&_DestinationHub.CallOpts, _domain)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_DestinationHub *DestinationHubCallerSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _DestinationHub.Contract.AmountAgents(&_DestinationHub.CallOpts, _domain)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_DestinationHub *DestinationHubCaller) AmountDomains(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "amountDomains")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_DestinationHub *DestinationHubSession) AmountDomains() (*big.Int, error) {
	return _DestinationHub.Contract.AmountDomains(&_DestinationHub.CallOpts)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_DestinationHub *DestinationHubCallerSession) AmountDomains() (*big.Int, error) {
	return _DestinationHub.Contract.AmountDomains(&_DestinationHub.CallOpts)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_DestinationHub *DestinationHubCaller) GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "getAgent", _domain, _agentIndex)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_DestinationHub *DestinationHubSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _DestinationHub.Contract.GetAgent(&_DestinationHub.CallOpts, _domain, _agentIndex)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_DestinationHub *DestinationHubCallerSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _DestinationHub.Contract.GetAgent(&_DestinationHub.CallOpts, _domain, _agentIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_DestinationHub *DestinationHubCaller) GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "getDomain", _domainIndex)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_DestinationHub *DestinationHubSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _DestinationHub.Contract.GetDomain(&_DestinationHub.CallOpts, _domainIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_DestinationHub *DestinationHubCallerSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _DestinationHub.Contract.GetDomain(&_DestinationHub.CallOpts, _domainIndex)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_DestinationHub *DestinationHubCaller) IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "isActiveAgent", _domain, _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_DestinationHub *DestinationHubSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _DestinationHub.Contract.IsActiveAgent(&_DestinationHub.CallOpts, _domain, _account)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_DestinationHub *DestinationHubCallerSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _DestinationHub.Contract.IsActiveAgent(&_DestinationHub.CallOpts, _domain, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_DestinationHub *DestinationHubCaller) IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "isActiveAgent0", _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_DestinationHub *DestinationHubSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _DestinationHub.Contract.IsActiveAgent0(&_DestinationHub.CallOpts, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_DestinationHub *DestinationHubCallerSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _DestinationHub.Contract.IsActiveAgent0(&_DestinationHub.CallOpts, _account)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_DestinationHub *DestinationHubCaller) IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "isActiveDomain", _domain)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_DestinationHub *DestinationHubSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _DestinationHub.Contract.IsActiveDomain(&_DestinationHub.CallOpts, _domain)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_DestinationHub *DestinationHubCallerSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _DestinationHub.Contract.IsActiveDomain(&_DestinationHub.CallOpts, _domain)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_DestinationHub *DestinationHubCaller) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "localDomain")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_DestinationHub *DestinationHubSession) LocalDomain() (uint32, error) {
	return _DestinationHub.Contract.LocalDomain(&_DestinationHub.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_DestinationHub *DestinationHubCallerSession) LocalDomain() (uint32, error) {
	return _DestinationHub.Contract.LocalDomain(&_DestinationHub.CallOpts)
}

// MirrorRoots is a free data retrieval call binding the contract method 0x79453331.
//
// Solidity: function mirrorRoots(uint32 , bytes32 ) view returns(address notary, uint96 submittedAt)
func (_DestinationHub *DestinationHubCaller) MirrorRoots(opts *bind.CallOpts, arg0 uint32, arg1 [32]byte) (struct {
	Notary      common.Address
	SubmittedAt *big.Int
}, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "mirrorRoots", arg0, arg1)

	outstruct := new(struct {
		Notary      common.Address
		SubmittedAt *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Notary = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.SubmittedAt = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// MirrorRoots is a free data retrieval call binding the contract method 0x79453331.
//
// Solidity: function mirrorRoots(uint32 , bytes32 ) view returns(address notary, uint96 submittedAt)
func (_DestinationHub *DestinationHubSession) MirrorRoots(arg0 uint32, arg1 [32]byte) (struct {
	Notary      common.Address
	SubmittedAt *big.Int
}, error) {
	return _DestinationHub.Contract.MirrorRoots(&_DestinationHub.CallOpts, arg0, arg1)
}

// MirrorRoots is a free data retrieval call binding the contract method 0x79453331.
//
// Solidity: function mirrorRoots(uint32 , bytes32 ) view returns(address notary, uint96 submittedAt)
func (_DestinationHub *DestinationHubCallerSession) MirrorRoots(arg0 uint32, arg1 [32]byte) (struct {
	Notary      common.Address
	SubmittedAt *big.Int
}, error) {
	return _DestinationHub.Contract.MirrorRoots(&_DestinationHub.CallOpts, arg0, arg1)
}

// Mirrors is a free data retrieval call binding the contract method 0x6356267b.
//
// Solidity: function mirrors(uint32 ) view returns(uint32 latestNonce, address latestNotary)
func (_DestinationHub *DestinationHubCaller) Mirrors(opts *bind.CallOpts, arg0 uint32) (struct {
	LatestNonce  uint32
	LatestNotary common.Address
}, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "mirrors", arg0)

	outstruct := new(struct {
		LatestNonce  uint32
		LatestNotary common.Address
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.LatestNonce = *abi.ConvertType(out[0], new(uint32)).(*uint32)
	outstruct.LatestNotary = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)

	return *outstruct, err

}

// Mirrors is a free data retrieval call binding the contract method 0x6356267b.
//
// Solidity: function mirrors(uint32 ) view returns(uint32 latestNonce, address latestNotary)
func (_DestinationHub *DestinationHubSession) Mirrors(arg0 uint32) (struct {
	LatestNonce  uint32
	LatestNotary common.Address
}, error) {
	return _DestinationHub.Contract.Mirrors(&_DestinationHub.CallOpts, arg0)
}

// Mirrors is a free data retrieval call binding the contract method 0x6356267b.
//
// Solidity: function mirrors(uint32 ) view returns(uint32 latestNonce, address latestNotary)
func (_DestinationHub *DestinationHubCallerSession) Mirrors(arg0 uint32) (struct {
	LatestNonce  uint32
	LatestNotary common.Address
}, error) {
	return _DestinationHub.Contract.Mirrors(&_DestinationHub.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_DestinationHub *DestinationHubCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_DestinationHub *DestinationHubSession) Owner() (common.Address, error) {
	return _DestinationHub.Contract.Owner(&_DestinationHub.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_DestinationHub *DestinationHubCallerSession) Owner() (common.Address, error) {
	return _DestinationHub.Contract.Owner(&_DestinationHub.CallOpts)
}

// SubmittedAt is a free data retrieval call binding the contract method 0x44792b83.
//
// Solidity: function submittedAt(uint32 _origin, bytes32 _root) view returns(uint96)
func (_DestinationHub *DestinationHubCaller) SubmittedAt(opts *bind.CallOpts, _origin uint32, _root [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "submittedAt", _origin, _root)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SubmittedAt is a free data retrieval call binding the contract method 0x44792b83.
//
// Solidity: function submittedAt(uint32 _origin, bytes32 _root) view returns(uint96)
func (_DestinationHub *DestinationHubSession) SubmittedAt(_origin uint32, _root [32]byte) (*big.Int, error) {
	return _DestinationHub.Contract.SubmittedAt(&_DestinationHub.CallOpts, _origin, _root)
}

// SubmittedAt is a free data retrieval call binding the contract method 0x44792b83.
//
// Solidity: function submittedAt(uint32 _origin, bytes32 _root) view returns(uint96)
func (_DestinationHub *DestinationHubCallerSession) SubmittedAt(_origin uint32, _root [32]byte) (*big.Int, error) {
	return _DestinationHub.Contract.SubmittedAt(&_DestinationHub.CallOpts, _origin, _root)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_DestinationHub *DestinationHubCaller) SystemRouter(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _DestinationHub.contract.Call(opts, &out, "systemRouter")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_DestinationHub *DestinationHubSession) SystemRouter() (common.Address, error) {
	return _DestinationHub.Contract.SystemRouter(&_DestinationHub.CallOpts)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_DestinationHub *DestinationHubCallerSession) SystemRouter() (common.Address, error) {
	return _DestinationHub.Contract.SystemRouter(&_DestinationHub.CallOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_DestinationHub *DestinationHubTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_DestinationHub *DestinationHubSession) RenounceOwnership() (*types.Transaction, error) {
	return _DestinationHub.Contract.RenounceOwnership(&_DestinationHub.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_DestinationHub *DestinationHubTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _DestinationHub.Contract.RenounceOwnership(&_DestinationHub.TransactOpts)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_DestinationHub *DestinationHubTransactor) SetSystemRouter(opts *bind.TransactOpts, _systemRouter common.Address) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "setSystemRouter", _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_DestinationHub *DestinationHubSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _DestinationHub.Contract.SetSystemRouter(&_DestinationHub.TransactOpts, _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_DestinationHub *DestinationHubTransactorSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _DestinationHub.Contract.SetSystemRouter(&_DestinationHub.TransactOpts, _systemRouter)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_DestinationHub *DestinationHubTransactor) SlashAgent(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "slashAgent", arg0, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_DestinationHub *DestinationHubSession) SlashAgent(arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _DestinationHub.Contract.SlashAgent(&_DestinationHub.TransactOpts, arg0, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_DestinationHub *DestinationHubTransactorSession) SlashAgent(arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _DestinationHub.Contract.SlashAgent(&_DestinationHub.TransactOpts, arg0, _callOrigin, _caller, _info)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_DestinationHub *DestinationHubTransactor) SubmitAttestation(opts *bind.TransactOpts, _attestation []byte) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "submitAttestation", _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_DestinationHub *DestinationHubSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _DestinationHub.Contract.SubmitAttestation(&_DestinationHub.TransactOpts, _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_DestinationHub *DestinationHubTransactorSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _DestinationHub.Contract.SubmitAttestation(&_DestinationHub.TransactOpts, _attestation)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_DestinationHub *DestinationHubTransactor) SubmitReport(opts *bind.TransactOpts, _report []byte) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "submitReport", _report)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_DestinationHub *DestinationHubSession) SubmitReport(_report []byte) (*types.Transaction, error) {
	return _DestinationHub.Contract.SubmitReport(&_DestinationHub.TransactOpts, _report)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_DestinationHub *DestinationHubTransactorSession) SubmitReport(_report []byte) (*types.Transaction, error) {
	return _DestinationHub.Contract.SubmitReport(&_DestinationHub.TransactOpts, _report)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_DestinationHub *DestinationHubTransactor) SyncAgents(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "syncAgents", arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_DestinationHub *DestinationHubSession) SyncAgents(arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _DestinationHub.Contract.SyncAgents(&_DestinationHub.TransactOpts, arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_DestinationHub *DestinationHubTransactorSession) SyncAgents(arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _DestinationHub.Contract.SyncAgents(&_DestinationHub.TransactOpts, arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_DestinationHub *DestinationHubTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _DestinationHub.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_DestinationHub *DestinationHubSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _DestinationHub.Contract.TransferOwnership(&_DestinationHub.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_DestinationHub *DestinationHubTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _DestinationHub.Contract.TransferOwnership(&_DestinationHub.TransactOpts, newOwner)
}

// DestinationHubAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the DestinationHub contract.
type DestinationHubAgentAddedIterator struct {
	Event *DestinationHubAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubAgentAdded represents a AgentAdded event raised by the DestinationHub contract.
type DestinationHubAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_DestinationHub *DestinationHubFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*DestinationHubAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &DestinationHubAgentAddedIterator{contract: _DestinationHub.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_DestinationHub *DestinationHubFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *DestinationHubAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubAgentAdded)
				if err := _DestinationHub.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_DestinationHub *DestinationHubFilterer) ParseAgentAdded(log types.Log) (*DestinationHubAgentAdded, error) {
	event := new(DestinationHubAgentAdded)
	if err := _DestinationHub.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the DestinationHub contract.
type DestinationHubAgentRemovedIterator struct {
	Event *DestinationHubAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubAgentRemoved represents a AgentRemoved event raised by the DestinationHub contract.
type DestinationHubAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_DestinationHub *DestinationHubFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*DestinationHubAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &DestinationHubAgentRemovedIterator{contract: _DestinationHub.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_DestinationHub *DestinationHubFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *DestinationHubAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubAgentRemoved)
				if err := _DestinationHub.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_DestinationHub *DestinationHubFilterer) ParseAgentRemoved(log types.Log) (*DestinationHubAgentRemoved, error) {
	event := new(DestinationHubAgentRemoved)
	if err := _DestinationHub.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubAttestationAcceptedIterator is returned from FilterAttestationAccepted and is used to iterate over the raw logs and unpacked data for AttestationAccepted events raised by the DestinationHub contract.
type DestinationHubAttestationAcceptedIterator struct {
	Event *DestinationHubAttestationAccepted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubAttestationAcceptedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubAttestationAccepted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubAttestationAccepted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubAttestationAcceptedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubAttestationAcceptedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubAttestationAccepted represents a AttestationAccepted event raised by the DestinationHub contract.
type DestinationHubAttestationAccepted struct {
	Guards      []common.Address
	Notaries    []common.Address
	Attestation []byte
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterAttestationAccepted is a free log retrieval operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_DestinationHub *DestinationHubFilterer) FilterAttestationAccepted(opts *bind.FilterOpts) (*DestinationHubAttestationAcceptedIterator, error) {

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return &DestinationHubAttestationAcceptedIterator{contract: _DestinationHub.contract, event: "AttestationAccepted", logs: logs, sub: sub}, nil
}

// WatchAttestationAccepted is a free log subscription operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_DestinationHub *DestinationHubFilterer) WatchAttestationAccepted(opts *bind.WatchOpts, sink chan<- *DestinationHubAttestationAccepted) (event.Subscription, error) {

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubAttestationAccepted)
				if err := _DestinationHub.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAttestationAccepted is a log parse operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_DestinationHub *DestinationHubFilterer) ParseAttestationAccepted(log types.Log) (*DestinationHubAttestationAccepted, error) {
	event := new(DestinationHubAttestationAccepted)
	if err := _DestinationHub.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the DestinationHub contract.
type DestinationHubDomainActivatedIterator struct {
	Event *DestinationHubDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubDomainActivated represents a DomainActivated event raised by the DestinationHub contract.
type DestinationHubDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_DestinationHub *DestinationHubFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*DestinationHubDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &DestinationHubDomainActivatedIterator{contract: _DestinationHub.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_DestinationHub *DestinationHubFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *DestinationHubDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubDomainActivated)
				if err := _DestinationHub.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_DestinationHub *DestinationHubFilterer) ParseDomainActivated(log types.Log) (*DestinationHubDomainActivated, error) {
	event := new(DestinationHubDomainActivated)
	if err := _DestinationHub.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the DestinationHub contract.
type DestinationHubDomainDeactivatedIterator struct {
	Event *DestinationHubDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubDomainDeactivated represents a DomainDeactivated event raised by the DestinationHub contract.
type DestinationHubDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_DestinationHub *DestinationHubFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*DestinationHubDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &DestinationHubDomainDeactivatedIterator{contract: _DestinationHub.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_DestinationHub *DestinationHubFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *DestinationHubDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubDomainDeactivated)
				if err := _DestinationHub.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_DestinationHub *DestinationHubFilterer) ParseDomainDeactivated(log types.Log) (*DestinationHubDomainDeactivated, error) {
	event := new(DestinationHubDomainDeactivated)
	if err := _DestinationHub.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the DestinationHub contract.
type DestinationHubInitializedIterator struct {
	Event *DestinationHubInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubInitialized represents a Initialized event raised by the DestinationHub contract.
type DestinationHubInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_DestinationHub *DestinationHubFilterer) FilterInitialized(opts *bind.FilterOpts) (*DestinationHubInitializedIterator, error) {

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &DestinationHubInitializedIterator{contract: _DestinationHub.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_DestinationHub *DestinationHubFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *DestinationHubInitialized) (event.Subscription, error) {

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubInitialized)
				if err := _DestinationHub.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_DestinationHub *DestinationHubFilterer) ParseInitialized(log types.Log) (*DestinationHubInitialized, error) {
	event := new(DestinationHubInitialized)
	if err := _DestinationHub.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DestinationHubOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the DestinationHub contract.
type DestinationHubOwnershipTransferredIterator struct {
	Event *DestinationHubOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DestinationHubOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DestinationHubOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DestinationHubOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DestinationHubOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DestinationHubOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DestinationHubOwnershipTransferred represents a OwnershipTransferred event raised by the DestinationHub contract.
type DestinationHubOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_DestinationHub *DestinationHubFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*DestinationHubOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _DestinationHub.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &DestinationHubOwnershipTransferredIterator{contract: _DestinationHub.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_DestinationHub *DestinationHubFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *DestinationHubOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _DestinationHub.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DestinationHubOwnershipTransferred)
				if err := _DestinationHub.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_DestinationHub *DestinationHubFilterer) ParseOwnershipTransferred(log types.Log) (*DestinationHubOwnershipTransferred, error) {
	event := new(DestinationHubOwnershipTransferred)
	if err := _DestinationHub.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DomainContextMetaData contains all meta data concerning the DomainContext contract.
var DomainContextMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"localDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"8d3638f4": "localDomain()",
	},
}

// DomainContextABI is the input ABI used to generate the binding from.
// Deprecated: Use DomainContextMetaData.ABI instead.
var DomainContextABI = DomainContextMetaData.ABI

// Deprecated: Use DomainContextMetaData.Sigs instead.
// DomainContextFuncSigs maps the 4-byte function signature to its string representation.
var DomainContextFuncSigs = DomainContextMetaData.Sigs

// DomainContext is an auto generated Go binding around an Ethereum contract.
type DomainContext struct {
	DomainContextCaller     // Read-only binding to the contract
	DomainContextTransactor // Write-only binding to the contract
	DomainContextFilterer   // Log filterer for contract events
}

// DomainContextCaller is an auto generated read-only Go binding around an Ethereum contract.
type DomainContextCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DomainContextTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DomainContextTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DomainContextFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DomainContextFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DomainContextSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DomainContextSession struct {
	Contract     *DomainContext    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// DomainContextCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DomainContextCallerSession struct {
	Contract *DomainContextCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// DomainContextTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DomainContextTransactorSession struct {
	Contract     *DomainContextTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// DomainContextRaw is an auto generated low-level Go binding around an Ethereum contract.
type DomainContextRaw struct {
	Contract *DomainContext // Generic contract binding to access the raw methods on
}

// DomainContextCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DomainContextCallerRaw struct {
	Contract *DomainContextCaller // Generic read-only contract binding to access the raw methods on
}

// DomainContextTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DomainContextTransactorRaw struct {
	Contract *DomainContextTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDomainContext creates a new instance of DomainContext, bound to a specific deployed contract.
func NewDomainContext(address common.Address, backend bind.ContractBackend) (*DomainContext, error) {
	contract, err := bindDomainContext(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &DomainContext{DomainContextCaller: DomainContextCaller{contract: contract}, DomainContextTransactor: DomainContextTransactor{contract: contract}, DomainContextFilterer: DomainContextFilterer{contract: contract}}, nil
}

// NewDomainContextCaller creates a new read-only instance of DomainContext, bound to a specific deployed contract.
func NewDomainContextCaller(address common.Address, caller bind.ContractCaller) (*DomainContextCaller, error) {
	contract, err := bindDomainContext(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DomainContextCaller{contract: contract}, nil
}

// NewDomainContextTransactor creates a new write-only instance of DomainContext, bound to a specific deployed contract.
func NewDomainContextTransactor(address common.Address, transactor bind.ContractTransactor) (*DomainContextTransactor, error) {
	contract, err := bindDomainContext(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DomainContextTransactor{contract: contract}, nil
}

// NewDomainContextFilterer creates a new log filterer instance of DomainContext, bound to a specific deployed contract.
func NewDomainContextFilterer(address common.Address, filterer bind.ContractFilterer) (*DomainContextFilterer, error) {
	contract, err := bindDomainContext(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DomainContextFilterer{contract: contract}, nil
}

// bindDomainContext binds a generic wrapper to an already deployed contract.
func bindDomainContext(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(DomainContextABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DomainContext *DomainContextRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DomainContext.Contract.DomainContextCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DomainContext *DomainContextRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DomainContext.Contract.DomainContextTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DomainContext *DomainContextRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DomainContext.Contract.DomainContextTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DomainContext *DomainContextCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DomainContext.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DomainContext *DomainContextTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DomainContext.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DomainContext *DomainContextTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DomainContext.Contract.contract.Transact(opts, method, params...)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_DomainContext *DomainContextCaller) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _DomainContext.contract.Call(opts, &out, "localDomain")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_DomainContext *DomainContextSession) LocalDomain() (uint32, error) {
	return _DomainContext.Contract.LocalDomain(&_DomainContext.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_DomainContext *DomainContextCallerSession) LocalDomain() (uint32, error) {
	return _DomainContext.Contract.LocalDomain(&_DomainContext.CallOpts)
}

// ECDSAMetaData contains all meta data concerning the ECDSA contract.
var ECDSAMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea26469706673582212204f210d1e9bf3262b50ef6a2766a9d06dd836cb358d720d0fe497b72031abe4fd64736f6c63430008110033",
}

// ECDSAABI is the input ABI used to generate the binding from.
// Deprecated: Use ECDSAMetaData.ABI instead.
var ECDSAABI = ECDSAMetaData.ABI

// ECDSABin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ECDSAMetaData.Bin instead.
var ECDSABin = ECDSAMetaData.Bin

// DeployECDSA deploys a new Ethereum contract, binding an instance of ECDSA to it.
func DeployECDSA(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ECDSA, error) {
	parsed, err := ECDSAMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ECDSABin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ECDSA{ECDSACaller: ECDSACaller{contract: contract}, ECDSATransactor: ECDSATransactor{contract: contract}, ECDSAFilterer: ECDSAFilterer{contract: contract}}, nil
}

// ECDSA is an auto generated Go binding around an Ethereum contract.
type ECDSA struct {
	ECDSACaller     // Read-only binding to the contract
	ECDSATransactor // Write-only binding to the contract
	ECDSAFilterer   // Log filterer for contract events
}

// ECDSACaller is an auto generated read-only Go binding around an Ethereum contract.
type ECDSACaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ECDSATransactor is an auto generated write-only Go binding around an Ethereum contract.
type ECDSATransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ECDSAFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ECDSAFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ECDSASession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ECDSASession struct {
	Contract     *ECDSA            // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ECDSACallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ECDSACallerSession struct {
	Contract *ECDSACaller  // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// ECDSATransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ECDSATransactorSession struct {
	Contract     *ECDSATransactor  // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ECDSARaw is an auto generated low-level Go binding around an Ethereum contract.
type ECDSARaw struct {
	Contract *ECDSA // Generic contract binding to access the raw methods on
}

// ECDSACallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ECDSACallerRaw struct {
	Contract *ECDSACaller // Generic read-only contract binding to access the raw methods on
}

// ECDSATransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ECDSATransactorRaw struct {
	Contract *ECDSATransactor // Generic write-only contract binding to access the raw methods on
}

// NewECDSA creates a new instance of ECDSA, bound to a specific deployed contract.
func NewECDSA(address common.Address, backend bind.ContractBackend) (*ECDSA, error) {
	contract, err := bindECDSA(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ECDSA{ECDSACaller: ECDSACaller{contract: contract}, ECDSATransactor: ECDSATransactor{contract: contract}, ECDSAFilterer: ECDSAFilterer{contract: contract}}, nil
}

// NewECDSACaller creates a new read-only instance of ECDSA, bound to a specific deployed contract.
func NewECDSACaller(address common.Address, caller bind.ContractCaller) (*ECDSACaller, error) {
	contract, err := bindECDSA(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ECDSACaller{contract: contract}, nil
}

// NewECDSATransactor creates a new write-only instance of ECDSA, bound to a specific deployed contract.
func NewECDSATransactor(address common.Address, transactor bind.ContractTransactor) (*ECDSATransactor, error) {
	contract, err := bindECDSA(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ECDSATransactor{contract: contract}, nil
}

// NewECDSAFilterer creates a new log filterer instance of ECDSA, bound to a specific deployed contract.
func NewECDSAFilterer(address common.Address, filterer bind.ContractFilterer) (*ECDSAFilterer, error) {
	contract, err := bindECDSA(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ECDSAFilterer{contract: contract}, nil
}

// bindECDSA binds a generic wrapper to an already deployed contract.
func bindECDSA(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ECDSAABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ECDSA *ECDSARaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ECDSA.Contract.ECDSACaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ECDSA *ECDSARaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSA.Contract.ECDSATransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ECDSA *ECDSARaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ECDSA.Contract.ECDSATransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ECDSA *ECDSACallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ECDSA.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ECDSA *ECDSATransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ECDSA.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ECDSA *ECDSATransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ECDSA.Contract.contract.Transact(opts, method, params...)
}

// EnumerableSetMetaData contains all meta data concerning the EnumerableSet contract.
var EnumerableSetMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122012313d4ca91835173a866c5c699788cca7f2622f52827cda677450e0c790e19d64736f6c63430008110033",
}

// EnumerableSetABI is the input ABI used to generate the binding from.
// Deprecated: Use EnumerableSetMetaData.ABI instead.
var EnumerableSetABI = EnumerableSetMetaData.ABI

// EnumerableSetBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use EnumerableSetMetaData.Bin instead.
var EnumerableSetBin = EnumerableSetMetaData.Bin

// DeployEnumerableSet deploys a new Ethereum contract, binding an instance of EnumerableSet to it.
func DeployEnumerableSet(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *EnumerableSet, error) {
	parsed, err := EnumerableSetMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(EnumerableSetBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &EnumerableSet{EnumerableSetCaller: EnumerableSetCaller{contract: contract}, EnumerableSetTransactor: EnumerableSetTransactor{contract: contract}, EnumerableSetFilterer: EnumerableSetFilterer{contract: contract}}, nil
}

// EnumerableSet is an auto generated Go binding around an Ethereum contract.
type EnumerableSet struct {
	EnumerableSetCaller     // Read-only binding to the contract
	EnumerableSetTransactor // Write-only binding to the contract
	EnumerableSetFilterer   // Log filterer for contract events
}

// EnumerableSetCaller is an auto generated read-only Go binding around an Ethereum contract.
type EnumerableSetCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EnumerableSetTransactor is an auto generated write-only Go binding around an Ethereum contract.
type EnumerableSetTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EnumerableSetFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type EnumerableSetFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EnumerableSetSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type EnumerableSetSession struct {
	Contract     *EnumerableSet    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// EnumerableSetCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type EnumerableSetCallerSession struct {
	Contract *EnumerableSetCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// EnumerableSetTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type EnumerableSetTransactorSession struct {
	Contract     *EnumerableSetTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// EnumerableSetRaw is an auto generated low-level Go binding around an Ethereum contract.
type EnumerableSetRaw struct {
	Contract *EnumerableSet // Generic contract binding to access the raw methods on
}

// EnumerableSetCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type EnumerableSetCallerRaw struct {
	Contract *EnumerableSetCaller // Generic read-only contract binding to access the raw methods on
}

// EnumerableSetTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type EnumerableSetTransactorRaw struct {
	Contract *EnumerableSetTransactor // Generic write-only contract binding to access the raw methods on
}

// NewEnumerableSet creates a new instance of EnumerableSet, bound to a specific deployed contract.
func NewEnumerableSet(address common.Address, backend bind.ContractBackend) (*EnumerableSet, error) {
	contract, err := bindEnumerableSet(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &EnumerableSet{EnumerableSetCaller: EnumerableSetCaller{contract: contract}, EnumerableSetTransactor: EnumerableSetTransactor{contract: contract}, EnumerableSetFilterer: EnumerableSetFilterer{contract: contract}}, nil
}

// NewEnumerableSetCaller creates a new read-only instance of EnumerableSet, bound to a specific deployed contract.
func NewEnumerableSetCaller(address common.Address, caller bind.ContractCaller) (*EnumerableSetCaller, error) {
	contract, err := bindEnumerableSet(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &EnumerableSetCaller{contract: contract}, nil
}

// NewEnumerableSetTransactor creates a new write-only instance of EnumerableSet, bound to a specific deployed contract.
func NewEnumerableSetTransactor(address common.Address, transactor bind.ContractTransactor) (*EnumerableSetTransactor, error) {
	contract, err := bindEnumerableSet(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &EnumerableSetTransactor{contract: contract}, nil
}

// NewEnumerableSetFilterer creates a new log filterer instance of EnumerableSet, bound to a specific deployed contract.
func NewEnumerableSetFilterer(address common.Address, filterer bind.ContractFilterer) (*EnumerableSetFilterer, error) {
	contract, err := bindEnumerableSet(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &EnumerableSetFilterer{contract: contract}, nil
}

// bindEnumerableSet binds a generic wrapper to an already deployed contract.
func bindEnumerableSet(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(EnumerableSetABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EnumerableSet *EnumerableSetRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _EnumerableSet.Contract.EnumerableSetCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EnumerableSet *EnumerableSetRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EnumerableSet.Contract.EnumerableSetTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EnumerableSet *EnumerableSetRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _EnumerableSet.Contract.EnumerableSetTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EnumerableSet *EnumerableSetCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _EnumerableSet.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EnumerableSet *EnumerableSetTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EnumerableSet.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EnumerableSet *EnumerableSetTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _EnumerableSet.Contract.contract.Transact(opts, method, params...)
}

// HeaderMetaData contains all meta data concerning the Header contract.
var HeaderMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea26469706673582212208015a550961486e3e36d42372459337d6d8e5881ebb0c37df3e63ed001070a9964736f6c63430008110033",
}

// HeaderABI is the input ABI used to generate the binding from.
// Deprecated: Use HeaderMetaData.ABI instead.
var HeaderABI = HeaderMetaData.ABI

// HeaderBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use HeaderMetaData.Bin instead.
var HeaderBin = HeaderMetaData.Bin

// DeployHeader deploys a new Ethereum contract, binding an instance of Header to it.
func DeployHeader(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Header, error) {
	parsed, err := HeaderMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(HeaderBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Header{HeaderCaller: HeaderCaller{contract: contract}, HeaderTransactor: HeaderTransactor{contract: contract}, HeaderFilterer: HeaderFilterer{contract: contract}}, nil
}

// Header is an auto generated Go binding around an Ethereum contract.
type Header struct {
	HeaderCaller     // Read-only binding to the contract
	HeaderTransactor // Write-only binding to the contract
	HeaderFilterer   // Log filterer for contract events
}

// HeaderCaller is an auto generated read-only Go binding around an Ethereum contract.
type HeaderCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HeaderTransactor is an auto generated write-only Go binding around an Ethereum contract.
type HeaderTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HeaderFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type HeaderFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HeaderSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type HeaderSession struct {
	Contract     *Header           // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// HeaderCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type HeaderCallerSession struct {
	Contract *HeaderCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// HeaderTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type HeaderTransactorSession struct {
	Contract     *HeaderTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// HeaderRaw is an auto generated low-level Go binding around an Ethereum contract.
type HeaderRaw struct {
	Contract *Header // Generic contract binding to access the raw methods on
}

// HeaderCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type HeaderCallerRaw struct {
	Contract *HeaderCaller // Generic read-only contract binding to access the raw methods on
}

// HeaderTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type HeaderTransactorRaw struct {
	Contract *HeaderTransactor // Generic write-only contract binding to access the raw methods on
}

// NewHeader creates a new instance of Header, bound to a specific deployed contract.
func NewHeader(address common.Address, backend bind.ContractBackend) (*Header, error) {
	contract, err := bindHeader(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Header{HeaderCaller: HeaderCaller{contract: contract}, HeaderTransactor: HeaderTransactor{contract: contract}, HeaderFilterer: HeaderFilterer{contract: contract}}, nil
}

// NewHeaderCaller creates a new read-only instance of Header, bound to a specific deployed contract.
func NewHeaderCaller(address common.Address, caller bind.ContractCaller) (*HeaderCaller, error) {
	contract, err := bindHeader(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &HeaderCaller{contract: contract}, nil
}

// NewHeaderTransactor creates a new write-only instance of Header, bound to a specific deployed contract.
func NewHeaderTransactor(address common.Address, transactor bind.ContractTransactor) (*HeaderTransactor, error) {
	contract, err := bindHeader(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &HeaderTransactor{contract: contract}, nil
}

// NewHeaderFilterer creates a new log filterer instance of Header, bound to a specific deployed contract.
func NewHeaderFilterer(address common.Address, filterer bind.ContractFilterer) (*HeaderFilterer, error) {
	contract, err := bindHeader(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &HeaderFilterer{contract: contract}, nil
}

// bindHeader binds a generic wrapper to an already deployed contract.
func bindHeader(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(HeaderABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Header *HeaderRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Header.Contract.HeaderCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Header *HeaderRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Header.Contract.HeaderTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Header *HeaderRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Header.Contract.HeaderTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Header *HeaderCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Header.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Header *HeaderTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Header.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Header *HeaderTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Header.Contract.contract.Transact(opts, method, params...)
}

// IMessageRecipientMetaData contains all meta data concerning the IMessageRecipient contract.
var IMessageRecipientMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_origin\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_nonce\",\"type\":\"uint32\"},{\"internalType\":\"bytes32\",\"name\":\"_sender\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"_rootTimestamp\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"_message\",\"type\":\"bytes\"}],\"name\":\"handle\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"e4d16d62": "handle(uint32,uint32,bytes32,uint256,bytes)",
	},
}

// IMessageRecipientABI is the input ABI used to generate the binding from.
// Deprecated: Use IMessageRecipientMetaData.ABI instead.
var IMessageRecipientABI = IMessageRecipientMetaData.ABI

// Deprecated: Use IMessageRecipientMetaData.Sigs instead.
// IMessageRecipientFuncSigs maps the 4-byte function signature to its string representation.
var IMessageRecipientFuncSigs = IMessageRecipientMetaData.Sigs

// IMessageRecipient is an auto generated Go binding around an Ethereum contract.
type IMessageRecipient struct {
	IMessageRecipientCaller     // Read-only binding to the contract
	IMessageRecipientTransactor // Write-only binding to the contract
	IMessageRecipientFilterer   // Log filterer for contract events
}

// IMessageRecipientCaller is an auto generated read-only Go binding around an Ethereum contract.
type IMessageRecipientCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IMessageRecipientTransactor is an auto generated write-only Go binding around an Ethereum contract.
type IMessageRecipientTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IMessageRecipientFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type IMessageRecipientFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IMessageRecipientSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type IMessageRecipientSession struct {
	Contract     *IMessageRecipient // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// IMessageRecipientCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type IMessageRecipientCallerSession struct {
	Contract *IMessageRecipientCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// IMessageRecipientTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type IMessageRecipientTransactorSession struct {
	Contract     *IMessageRecipientTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// IMessageRecipientRaw is an auto generated low-level Go binding around an Ethereum contract.
type IMessageRecipientRaw struct {
	Contract *IMessageRecipient // Generic contract binding to access the raw methods on
}

// IMessageRecipientCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type IMessageRecipientCallerRaw struct {
	Contract *IMessageRecipientCaller // Generic read-only contract binding to access the raw methods on
}

// IMessageRecipientTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type IMessageRecipientTransactorRaw struct {
	Contract *IMessageRecipientTransactor // Generic write-only contract binding to access the raw methods on
}

// NewIMessageRecipient creates a new instance of IMessageRecipient, bound to a specific deployed contract.
func NewIMessageRecipient(address common.Address, backend bind.ContractBackend) (*IMessageRecipient, error) {
	contract, err := bindIMessageRecipient(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &IMessageRecipient{IMessageRecipientCaller: IMessageRecipientCaller{contract: contract}, IMessageRecipientTransactor: IMessageRecipientTransactor{contract: contract}, IMessageRecipientFilterer: IMessageRecipientFilterer{contract: contract}}, nil
}

// NewIMessageRecipientCaller creates a new read-only instance of IMessageRecipient, bound to a specific deployed contract.
func NewIMessageRecipientCaller(address common.Address, caller bind.ContractCaller) (*IMessageRecipientCaller, error) {
	contract, err := bindIMessageRecipient(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &IMessageRecipientCaller{contract: contract}, nil
}

// NewIMessageRecipientTransactor creates a new write-only instance of IMessageRecipient, bound to a specific deployed contract.
func NewIMessageRecipientTransactor(address common.Address, transactor bind.ContractTransactor) (*IMessageRecipientTransactor, error) {
	contract, err := bindIMessageRecipient(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &IMessageRecipientTransactor{contract: contract}, nil
}

// NewIMessageRecipientFilterer creates a new log filterer instance of IMessageRecipient, bound to a specific deployed contract.
func NewIMessageRecipientFilterer(address common.Address, filterer bind.ContractFilterer) (*IMessageRecipientFilterer, error) {
	contract, err := bindIMessageRecipient(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &IMessageRecipientFilterer{contract: contract}, nil
}

// bindIMessageRecipient binds a generic wrapper to an already deployed contract.
func bindIMessageRecipient(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(IMessageRecipientABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IMessageRecipient *IMessageRecipientRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _IMessageRecipient.Contract.IMessageRecipientCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IMessageRecipient *IMessageRecipientRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IMessageRecipient.Contract.IMessageRecipientTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IMessageRecipient *IMessageRecipientRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IMessageRecipient.Contract.IMessageRecipientTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IMessageRecipient *IMessageRecipientCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _IMessageRecipient.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IMessageRecipient *IMessageRecipientTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IMessageRecipient.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IMessageRecipient *IMessageRecipientTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IMessageRecipient.Contract.contract.Transact(opts, method, params...)
}

// Handle is a paid mutator transaction binding the contract method 0xe4d16d62.
//
// Solidity: function handle(uint32 _origin, uint32 _nonce, bytes32 _sender, uint256 _rootTimestamp, bytes _message) returns()
func (_IMessageRecipient *IMessageRecipientTransactor) Handle(opts *bind.TransactOpts, _origin uint32, _nonce uint32, _sender [32]byte, _rootTimestamp *big.Int, _message []byte) (*types.Transaction, error) {
	return _IMessageRecipient.contract.Transact(opts, "handle", _origin, _nonce, _sender, _rootTimestamp, _message)
}

// Handle is a paid mutator transaction binding the contract method 0xe4d16d62.
//
// Solidity: function handle(uint32 _origin, uint32 _nonce, bytes32 _sender, uint256 _rootTimestamp, bytes _message) returns()
func (_IMessageRecipient *IMessageRecipientSession) Handle(_origin uint32, _nonce uint32, _sender [32]byte, _rootTimestamp *big.Int, _message []byte) (*types.Transaction, error) {
	return _IMessageRecipient.Contract.Handle(&_IMessageRecipient.TransactOpts, _origin, _nonce, _sender, _rootTimestamp, _message)
}

// Handle is a paid mutator transaction binding the contract method 0xe4d16d62.
//
// Solidity: function handle(uint32 _origin, uint32 _nonce, bytes32 _sender, uint256 _rootTimestamp, bytes _message) returns()
func (_IMessageRecipient *IMessageRecipientTransactorSession) Handle(_origin uint32, _nonce uint32, _sender [32]byte, _rootTimestamp *big.Int, _message []byte) (*types.Transaction, error) {
	return _IMessageRecipient.Contract.Handle(&_IMessageRecipient.TransactOpts, _origin, _nonce, _sender, _rootTimestamp, _message)
}

// ISystemRouterMetaData contains all meta data concerning the ISystemRouter contract.
var ISystemRouterMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_destination\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_optimisticSeconds\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_recipient\",\"type\":\"uint8\"},{\"internalType\":\"bytes\",\"name\":\"_data\",\"type\":\"bytes\"}],\"name\":\"systemCall\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_destination\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_optimisticSeconds\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity[]\",\"name\":\"_recipients\",\"type\":\"uint8[]\"},{\"internalType\":\"bytes\",\"name\":\"_data\",\"type\":\"bytes\"}],\"name\":\"systemMultiCall\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_destination\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_optimisticSeconds\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_recipient\",\"type\":\"uint8\"},{\"internalType\":\"bytes[]\",\"name\":\"_dataArray\",\"type\":\"bytes[]\"}],\"name\":\"systemMultiCall\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_destination\",\"type\":\"uint32\"},{\"internalType\":\"uint32\",\"name\":\"_optimisticSeconds\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity[]\",\"name\":\"_recipients\",\"type\":\"uint8[]\"},{\"internalType\":\"bytes[]\",\"name\":\"_dataArray\",\"type\":\"bytes[]\"}],\"name\":\"systemMultiCall\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"bf65bc46": "systemCall(uint32,uint32,uint8,bytes)",
		"4491b24d": "systemMultiCall(uint32,uint32,uint8,bytes[])",
		"2ec0b338": "systemMultiCall(uint32,uint32,uint8[],bytes)",
		"de58387b": "systemMultiCall(uint32,uint32,uint8[],bytes[])",
	},
}

// ISystemRouterABI is the input ABI used to generate the binding from.
// Deprecated: Use ISystemRouterMetaData.ABI instead.
var ISystemRouterABI = ISystemRouterMetaData.ABI

// Deprecated: Use ISystemRouterMetaData.Sigs instead.
// ISystemRouterFuncSigs maps the 4-byte function signature to its string representation.
var ISystemRouterFuncSigs = ISystemRouterMetaData.Sigs

// ISystemRouter is an auto generated Go binding around an Ethereum contract.
type ISystemRouter struct {
	ISystemRouterCaller     // Read-only binding to the contract
	ISystemRouterTransactor // Write-only binding to the contract
	ISystemRouterFilterer   // Log filterer for contract events
}

// ISystemRouterCaller is an auto generated read-only Go binding around an Ethereum contract.
type ISystemRouterCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISystemRouterTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ISystemRouterTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISystemRouterFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ISystemRouterFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISystemRouterSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ISystemRouterSession struct {
	Contract     *ISystemRouter    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ISystemRouterCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ISystemRouterCallerSession struct {
	Contract *ISystemRouterCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// ISystemRouterTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ISystemRouterTransactorSession struct {
	Contract     *ISystemRouterTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// ISystemRouterRaw is an auto generated low-level Go binding around an Ethereum contract.
type ISystemRouterRaw struct {
	Contract *ISystemRouter // Generic contract binding to access the raw methods on
}

// ISystemRouterCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ISystemRouterCallerRaw struct {
	Contract *ISystemRouterCaller // Generic read-only contract binding to access the raw methods on
}

// ISystemRouterTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ISystemRouterTransactorRaw struct {
	Contract *ISystemRouterTransactor // Generic write-only contract binding to access the raw methods on
}

// NewISystemRouter creates a new instance of ISystemRouter, bound to a specific deployed contract.
func NewISystemRouter(address common.Address, backend bind.ContractBackend) (*ISystemRouter, error) {
	contract, err := bindISystemRouter(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ISystemRouter{ISystemRouterCaller: ISystemRouterCaller{contract: contract}, ISystemRouterTransactor: ISystemRouterTransactor{contract: contract}, ISystemRouterFilterer: ISystemRouterFilterer{contract: contract}}, nil
}

// NewISystemRouterCaller creates a new read-only instance of ISystemRouter, bound to a specific deployed contract.
func NewISystemRouterCaller(address common.Address, caller bind.ContractCaller) (*ISystemRouterCaller, error) {
	contract, err := bindISystemRouter(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ISystemRouterCaller{contract: contract}, nil
}

// NewISystemRouterTransactor creates a new write-only instance of ISystemRouter, bound to a specific deployed contract.
func NewISystemRouterTransactor(address common.Address, transactor bind.ContractTransactor) (*ISystemRouterTransactor, error) {
	contract, err := bindISystemRouter(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ISystemRouterTransactor{contract: contract}, nil
}

// NewISystemRouterFilterer creates a new log filterer instance of ISystemRouter, bound to a specific deployed contract.
func NewISystemRouterFilterer(address common.Address, filterer bind.ContractFilterer) (*ISystemRouterFilterer, error) {
	contract, err := bindISystemRouter(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ISystemRouterFilterer{contract: contract}, nil
}

// bindISystemRouter binds a generic wrapper to an already deployed contract.
func bindISystemRouter(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ISystemRouterABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ISystemRouter *ISystemRouterRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ISystemRouter.Contract.ISystemRouterCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ISystemRouter *ISystemRouterRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISystemRouter.Contract.ISystemRouterTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ISystemRouter *ISystemRouterRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ISystemRouter.Contract.ISystemRouterTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ISystemRouter *ISystemRouterCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ISystemRouter.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ISystemRouter *ISystemRouterTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISystemRouter.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ISystemRouter *ISystemRouterTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ISystemRouter.Contract.contract.Transact(opts, method, params...)
}

// SystemCall is a paid mutator transaction binding the contract method 0xbf65bc46.
//
// Solidity: function systemCall(uint32 _destination, uint32 _optimisticSeconds, uint8 _recipient, bytes _data) returns()
func (_ISystemRouter *ISystemRouterTransactor) SystemCall(opts *bind.TransactOpts, _destination uint32, _optimisticSeconds uint32, _recipient uint8, _data []byte) (*types.Transaction, error) {
	return _ISystemRouter.contract.Transact(opts, "systemCall", _destination, _optimisticSeconds, _recipient, _data)
}

// SystemCall is a paid mutator transaction binding the contract method 0xbf65bc46.
//
// Solidity: function systemCall(uint32 _destination, uint32 _optimisticSeconds, uint8 _recipient, bytes _data) returns()
func (_ISystemRouter *ISystemRouterSession) SystemCall(_destination uint32, _optimisticSeconds uint32, _recipient uint8, _data []byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemCall(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipient, _data)
}

// SystemCall is a paid mutator transaction binding the contract method 0xbf65bc46.
//
// Solidity: function systemCall(uint32 _destination, uint32 _optimisticSeconds, uint8 _recipient, bytes _data) returns()
func (_ISystemRouter *ISystemRouterTransactorSession) SystemCall(_destination uint32, _optimisticSeconds uint32, _recipient uint8, _data []byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemCall(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipient, _data)
}

// SystemMultiCall is a paid mutator transaction binding the contract method 0x2ec0b338.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8[] _recipients, bytes _data) returns()
func (_ISystemRouter *ISystemRouterTransactor) SystemMultiCall(opts *bind.TransactOpts, _destination uint32, _optimisticSeconds uint32, _recipients []uint8, _data []byte) (*types.Transaction, error) {
	return _ISystemRouter.contract.Transact(opts, "systemMultiCall", _destination, _optimisticSeconds, _recipients, _data)
}

// SystemMultiCall is a paid mutator transaction binding the contract method 0x2ec0b338.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8[] _recipients, bytes _data) returns()
func (_ISystemRouter *ISystemRouterSession) SystemMultiCall(_destination uint32, _optimisticSeconds uint32, _recipients []uint8, _data []byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemMultiCall(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipients, _data)
}

// SystemMultiCall is a paid mutator transaction binding the contract method 0x2ec0b338.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8[] _recipients, bytes _data) returns()
func (_ISystemRouter *ISystemRouterTransactorSession) SystemMultiCall(_destination uint32, _optimisticSeconds uint32, _recipients []uint8, _data []byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemMultiCall(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipients, _data)
}

// SystemMultiCall0 is a paid mutator transaction binding the contract method 0x4491b24d.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8 _recipient, bytes[] _dataArray) returns()
func (_ISystemRouter *ISystemRouterTransactor) SystemMultiCall0(opts *bind.TransactOpts, _destination uint32, _optimisticSeconds uint32, _recipient uint8, _dataArray [][]byte) (*types.Transaction, error) {
	return _ISystemRouter.contract.Transact(opts, "systemMultiCall0", _destination, _optimisticSeconds, _recipient, _dataArray)
}

// SystemMultiCall0 is a paid mutator transaction binding the contract method 0x4491b24d.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8 _recipient, bytes[] _dataArray) returns()
func (_ISystemRouter *ISystemRouterSession) SystemMultiCall0(_destination uint32, _optimisticSeconds uint32, _recipient uint8, _dataArray [][]byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemMultiCall0(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipient, _dataArray)
}

// SystemMultiCall0 is a paid mutator transaction binding the contract method 0x4491b24d.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8 _recipient, bytes[] _dataArray) returns()
func (_ISystemRouter *ISystemRouterTransactorSession) SystemMultiCall0(_destination uint32, _optimisticSeconds uint32, _recipient uint8, _dataArray [][]byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemMultiCall0(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipient, _dataArray)
}

// SystemMultiCall1 is a paid mutator transaction binding the contract method 0xde58387b.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8[] _recipients, bytes[] _dataArray) returns()
func (_ISystemRouter *ISystemRouterTransactor) SystemMultiCall1(opts *bind.TransactOpts, _destination uint32, _optimisticSeconds uint32, _recipients []uint8, _dataArray [][]byte) (*types.Transaction, error) {
	return _ISystemRouter.contract.Transact(opts, "systemMultiCall1", _destination, _optimisticSeconds, _recipients, _dataArray)
}

// SystemMultiCall1 is a paid mutator transaction binding the contract method 0xde58387b.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8[] _recipients, bytes[] _dataArray) returns()
func (_ISystemRouter *ISystemRouterSession) SystemMultiCall1(_destination uint32, _optimisticSeconds uint32, _recipients []uint8, _dataArray [][]byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemMultiCall1(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipients, _dataArray)
}

// SystemMultiCall1 is a paid mutator transaction binding the contract method 0xde58387b.
//
// Solidity: function systemMultiCall(uint32 _destination, uint32 _optimisticSeconds, uint8[] _recipients, bytes[] _dataArray) returns()
func (_ISystemRouter *ISystemRouterTransactorSession) SystemMultiCall1(_destination uint32, _optimisticSeconds uint32, _recipients []uint8, _dataArray [][]byte) (*types.Transaction, error) {
	return _ISystemRouter.Contract.SystemMultiCall1(&_ISystemRouter.TransactOpts, _destination, _optimisticSeconds, _recipients, _dataArray)
}

// InitializableMetaData contains all meta data concerning the Initializable contract.
var InitializableMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"}]",
}

// InitializableABI is the input ABI used to generate the binding from.
// Deprecated: Use InitializableMetaData.ABI instead.
var InitializableABI = InitializableMetaData.ABI

// Initializable is an auto generated Go binding around an Ethereum contract.
type Initializable struct {
	InitializableCaller     // Read-only binding to the contract
	InitializableTransactor // Write-only binding to the contract
	InitializableFilterer   // Log filterer for contract events
}

// InitializableCaller is an auto generated read-only Go binding around an Ethereum contract.
type InitializableCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// InitializableTransactor is an auto generated write-only Go binding around an Ethereum contract.
type InitializableTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// InitializableFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type InitializableFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// InitializableSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type InitializableSession struct {
	Contract     *Initializable    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// InitializableCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type InitializableCallerSession struct {
	Contract *InitializableCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// InitializableTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type InitializableTransactorSession struct {
	Contract     *InitializableTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// InitializableRaw is an auto generated low-level Go binding around an Ethereum contract.
type InitializableRaw struct {
	Contract *Initializable // Generic contract binding to access the raw methods on
}

// InitializableCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type InitializableCallerRaw struct {
	Contract *InitializableCaller // Generic read-only contract binding to access the raw methods on
}

// InitializableTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type InitializableTransactorRaw struct {
	Contract *InitializableTransactor // Generic write-only contract binding to access the raw methods on
}

// NewInitializable creates a new instance of Initializable, bound to a specific deployed contract.
func NewInitializable(address common.Address, backend bind.ContractBackend) (*Initializable, error) {
	contract, err := bindInitializable(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Initializable{InitializableCaller: InitializableCaller{contract: contract}, InitializableTransactor: InitializableTransactor{contract: contract}, InitializableFilterer: InitializableFilterer{contract: contract}}, nil
}

// NewInitializableCaller creates a new read-only instance of Initializable, bound to a specific deployed contract.
func NewInitializableCaller(address common.Address, caller bind.ContractCaller) (*InitializableCaller, error) {
	contract, err := bindInitializable(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &InitializableCaller{contract: contract}, nil
}

// NewInitializableTransactor creates a new write-only instance of Initializable, bound to a specific deployed contract.
func NewInitializableTransactor(address common.Address, transactor bind.ContractTransactor) (*InitializableTransactor, error) {
	contract, err := bindInitializable(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &InitializableTransactor{contract: contract}, nil
}

// NewInitializableFilterer creates a new log filterer instance of Initializable, bound to a specific deployed contract.
func NewInitializableFilterer(address common.Address, filterer bind.ContractFilterer) (*InitializableFilterer, error) {
	contract, err := bindInitializable(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &InitializableFilterer{contract: contract}, nil
}

// bindInitializable binds a generic wrapper to an already deployed contract.
func bindInitializable(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(InitializableABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Initializable *InitializableRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Initializable.Contract.InitializableCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Initializable *InitializableRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Initializable.Contract.InitializableTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Initializable *InitializableRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Initializable.Contract.InitializableTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Initializable *InitializableCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Initializable.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Initializable *InitializableTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Initializable.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Initializable *InitializableTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Initializable.Contract.contract.Transact(opts, method, params...)
}

// InitializableInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the Initializable contract.
type InitializableInitializedIterator struct {
	Event *InitializableInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *InitializableInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(InitializableInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(InitializableInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *InitializableInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *InitializableInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// InitializableInitialized represents a Initialized event raised by the Initializable contract.
type InitializableInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Initializable *InitializableFilterer) FilterInitialized(opts *bind.FilterOpts) (*InitializableInitializedIterator, error) {

	logs, sub, err := _Initializable.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &InitializableInitializedIterator{contract: _Initializable.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Initializable *InitializableFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *InitializableInitialized) (event.Subscription, error) {

	logs, sub, err := _Initializable.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(InitializableInitialized)
				if err := _Initializable.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_Initializable *InitializableFilterer) ParseInitialized(log types.Log) (*InitializableInitialized, error) {
	event := new(InitializableInitialized)
	if err := _Initializable.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// LocalDomainContextMetaData contains all meta data concerning the LocalDomainContext contract.
var LocalDomainContextMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"localDomain_\",\"type\":\"uint32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"localDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"8d3638f4": "localDomain()",
	},
	Bin: "0x60a060405234801561001057600080fd5b5060405161011f38038061011f83398101604081905261002f9161003d565b63ffffffff1660805261006a565b60006020828403121561004f57600080fd5b815163ffffffff8116811461006357600080fd5b9392505050565b608051609d6100826000396000602f0152609d6000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80638d3638f414602d575b600080fd5b7f000000000000000000000000000000000000000000000000000000000000000060405163ffffffff909116815260200160405180910390f3fea26469706673582212208ac875c125509365fb4fee4c2db31a7e5548d28eff240dc2942bc35b1c807b5a64736f6c63430008110033",
}

// LocalDomainContextABI is the input ABI used to generate the binding from.
// Deprecated: Use LocalDomainContextMetaData.ABI instead.
var LocalDomainContextABI = LocalDomainContextMetaData.ABI

// Deprecated: Use LocalDomainContextMetaData.Sigs instead.
// LocalDomainContextFuncSigs maps the 4-byte function signature to its string representation.
var LocalDomainContextFuncSigs = LocalDomainContextMetaData.Sigs

// LocalDomainContextBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use LocalDomainContextMetaData.Bin instead.
var LocalDomainContextBin = LocalDomainContextMetaData.Bin

// DeployLocalDomainContext deploys a new Ethereum contract, binding an instance of LocalDomainContext to it.
func DeployLocalDomainContext(auth *bind.TransactOpts, backend bind.ContractBackend, localDomain_ uint32) (common.Address, *types.Transaction, *LocalDomainContext, error) {
	parsed, err := LocalDomainContextMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(LocalDomainContextBin), backend, localDomain_)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &LocalDomainContext{LocalDomainContextCaller: LocalDomainContextCaller{contract: contract}, LocalDomainContextTransactor: LocalDomainContextTransactor{contract: contract}, LocalDomainContextFilterer: LocalDomainContextFilterer{contract: contract}}, nil
}

// LocalDomainContext is an auto generated Go binding around an Ethereum contract.
type LocalDomainContext struct {
	LocalDomainContextCaller     // Read-only binding to the contract
	LocalDomainContextTransactor // Write-only binding to the contract
	LocalDomainContextFilterer   // Log filterer for contract events
}

// LocalDomainContextCaller is an auto generated read-only Go binding around an Ethereum contract.
type LocalDomainContextCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// LocalDomainContextTransactor is an auto generated write-only Go binding around an Ethereum contract.
type LocalDomainContextTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// LocalDomainContextFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type LocalDomainContextFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// LocalDomainContextSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type LocalDomainContextSession struct {
	Contract     *LocalDomainContext // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// LocalDomainContextCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type LocalDomainContextCallerSession struct {
	Contract *LocalDomainContextCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// LocalDomainContextTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type LocalDomainContextTransactorSession struct {
	Contract     *LocalDomainContextTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// LocalDomainContextRaw is an auto generated low-level Go binding around an Ethereum contract.
type LocalDomainContextRaw struct {
	Contract *LocalDomainContext // Generic contract binding to access the raw methods on
}

// LocalDomainContextCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type LocalDomainContextCallerRaw struct {
	Contract *LocalDomainContextCaller // Generic read-only contract binding to access the raw methods on
}

// LocalDomainContextTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type LocalDomainContextTransactorRaw struct {
	Contract *LocalDomainContextTransactor // Generic write-only contract binding to access the raw methods on
}

// NewLocalDomainContext creates a new instance of LocalDomainContext, bound to a specific deployed contract.
func NewLocalDomainContext(address common.Address, backend bind.ContractBackend) (*LocalDomainContext, error) {
	contract, err := bindLocalDomainContext(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &LocalDomainContext{LocalDomainContextCaller: LocalDomainContextCaller{contract: contract}, LocalDomainContextTransactor: LocalDomainContextTransactor{contract: contract}, LocalDomainContextFilterer: LocalDomainContextFilterer{contract: contract}}, nil
}

// NewLocalDomainContextCaller creates a new read-only instance of LocalDomainContext, bound to a specific deployed contract.
func NewLocalDomainContextCaller(address common.Address, caller bind.ContractCaller) (*LocalDomainContextCaller, error) {
	contract, err := bindLocalDomainContext(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &LocalDomainContextCaller{contract: contract}, nil
}

// NewLocalDomainContextTransactor creates a new write-only instance of LocalDomainContext, bound to a specific deployed contract.
func NewLocalDomainContextTransactor(address common.Address, transactor bind.ContractTransactor) (*LocalDomainContextTransactor, error) {
	contract, err := bindLocalDomainContext(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &LocalDomainContextTransactor{contract: contract}, nil
}

// NewLocalDomainContextFilterer creates a new log filterer instance of LocalDomainContext, bound to a specific deployed contract.
func NewLocalDomainContextFilterer(address common.Address, filterer bind.ContractFilterer) (*LocalDomainContextFilterer, error) {
	contract, err := bindLocalDomainContext(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &LocalDomainContextFilterer{contract: contract}, nil
}

// bindLocalDomainContext binds a generic wrapper to an already deployed contract.
func bindLocalDomainContext(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(LocalDomainContextABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_LocalDomainContext *LocalDomainContextRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _LocalDomainContext.Contract.LocalDomainContextCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_LocalDomainContext *LocalDomainContextRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _LocalDomainContext.Contract.LocalDomainContextTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_LocalDomainContext *LocalDomainContextRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _LocalDomainContext.Contract.LocalDomainContextTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_LocalDomainContext *LocalDomainContextCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _LocalDomainContext.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_LocalDomainContext *LocalDomainContextTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _LocalDomainContext.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_LocalDomainContext *LocalDomainContextTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _LocalDomainContext.Contract.contract.Transact(opts, method, params...)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_LocalDomainContext *LocalDomainContextCaller) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _LocalDomainContext.contract.Call(opts, &out, "localDomain")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_LocalDomainContext *LocalDomainContextSession) LocalDomain() (uint32, error) {
	return _LocalDomainContext.Contract.LocalDomain(&_LocalDomainContext.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_LocalDomainContext *LocalDomainContextCallerSession) LocalDomain() (uint32, error) {
	return _LocalDomainContext.Contract.LocalDomain(&_LocalDomainContext.CallOpts)
}

// MerkleLibMetaData contains all meta data concerning the MerkleLib contract.
var MerkleLibMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea2646970667358221220b2ec13e5c38b4ed19a400c1e53dccc09f8dd23e4793915f467e6b5293f42034c64736f6c63430008110033",
}

// MerkleLibABI is the input ABI used to generate the binding from.
// Deprecated: Use MerkleLibMetaData.ABI instead.
var MerkleLibABI = MerkleLibMetaData.ABI

// MerkleLibBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use MerkleLibMetaData.Bin instead.
var MerkleLibBin = MerkleLibMetaData.Bin

// DeployMerkleLib deploys a new Ethereum contract, binding an instance of MerkleLib to it.
func DeployMerkleLib(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *MerkleLib, error) {
	parsed, err := MerkleLibMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(MerkleLibBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &MerkleLib{MerkleLibCaller: MerkleLibCaller{contract: contract}, MerkleLibTransactor: MerkleLibTransactor{contract: contract}, MerkleLibFilterer: MerkleLibFilterer{contract: contract}}, nil
}

// MerkleLib is an auto generated Go binding around an Ethereum contract.
type MerkleLib struct {
	MerkleLibCaller     // Read-only binding to the contract
	MerkleLibTransactor // Write-only binding to the contract
	MerkleLibFilterer   // Log filterer for contract events
}

// MerkleLibCaller is an auto generated read-only Go binding around an Ethereum contract.
type MerkleLibCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MerkleLibTransactor is an auto generated write-only Go binding around an Ethereum contract.
type MerkleLibTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MerkleLibFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type MerkleLibFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MerkleLibSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type MerkleLibSession struct {
	Contract     *MerkleLib        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// MerkleLibCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type MerkleLibCallerSession struct {
	Contract *MerkleLibCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// MerkleLibTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type MerkleLibTransactorSession struct {
	Contract     *MerkleLibTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// MerkleLibRaw is an auto generated low-level Go binding around an Ethereum contract.
type MerkleLibRaw struct {
	Contract *MerkleLib // Generic contract binding to access the raw methods on
}

// MerkleLibCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type MerkleLibCallerRaw struct {
	Contract *MerkleLibCaller // Generic read-only contract binding to access the raw methods on
}

// MerkleLibTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type MerkleLibTransactorRaw struct {
	Contract *MerkleLibTransactor // Generic write-only contract binding to access the raw methods on
}

// NewMerkleLib creates a new instance of MerkleLib, bound to a specific deployed contract.
func NewMerkleLib(address common.Address, backend bind.ContractBackend) (*MerkleLib, error) {
	contract, err := bindMerkleLib(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &MerkleLib{MerkleLibCaller: MerkleLibCaller{contract: contract}, MerkleLibTransactor: MerkleLibTransactor{contract: contract}, MerkleLibFilterer: MerkleLibFilterer{contract: contract}}, nil
}

// NewMerkleLibCaller creates a new read-only instance of MerkleLib, bound to a specific deployed contract.
func NewMerkleLibCaller(address common.Address, caller bind.ContractCaller) (*MerkleLibCaller, error) {
	contract, err := bindMerkleLib(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &MerkleLibCaller{contract: contract}, nil
}

// NewMerkleLibTransactor creates a new write-only instance of MerkleLib, bound to a specific deployed contract.
func NewMerkleLibTransactor(address common.Address, transactor bind.ContractTransactor) (*MerkleLibTransactor, error) {
	contract, err := bindMerkleLib(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &MerkleLibTransactor{contract: contract}, nil
}

// NewMerkleLibFilterer creates a new log filterer instance of MerkleLib, bound to a specific deployed contract.
func NewMerkleLibFilterer(address common.Address, filterer bind.ContractFilterer) (*MerkleLibFilterer, error) {
	contract, err := bindMerkleLib(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &MerkleLibFilterer{contract: contract}, nil
}

// bindMerkleLib binds a generic wrapper to an already deployed contract.
func bindMerkleLib(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(MerkleLibABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_MerkleLib *MerkleLibRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _MerkleLib.Contract.MerkleLibCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_MerkleLib *MerkleLibRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MerkleLib.Contract.MerkleLibTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_MerkleLib *MerkleLibRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _MerkleLib.Contract.MerkleLibTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_MerkleLib *MerkleLibCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _MerkleLib.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_MerkleLib *MerkleLibTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _MerkleLib.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_MerkleLib *MerkleLibTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _MerkleLib.Contract.contract.Transact(opts, method, params...)
}

// MessageMetaData contains all meta data concerning the Message contract.
var MessageMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122081fef62a0d828746ba60de31dbba7b72ef23bd83f21cec91a5f996d94fee01f164736f6c63430008110033",
}

// MessageABI is the input ABI used to generate the binding from.
// Deprecated: Use MessageMetaData.ABI instead.
var MessageABI = MessageMetaData.ABI

// MessageBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use MessageMetaData.Bin instead.
var MessageBin = MessageMetaData.Bin

// DeployMessage deploys a new Ethereum contract, binding an instance of Message to it.
func DeployMessage(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Message, error) {
	parsed, err := MessageMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(MessageBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Message{MessageCaller: MessageCaller{contract: contract}, MessageTransactor: MessageTransactor{contract: contract}, MessageFilterer: MessageFilterer{contract: contract}}, nil
}

// Message is an auto generated Go binding around an Ethereum contract.
type Message struct {
	MessageCaller     // Read-only binding to the contract
	MessageTransactor // Write-only binding to the contract
	MessageFilterer   // Log filterer for contract events
}

// MessageCaller is an auto generated read-only Go binding around an Ethereum contract.
type MessageCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MessageTransactor is an auto generated write-only Go binding around an Ethereum contract.
type MessageTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MessageFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type MessageFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// MessageSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type MessageSession struct {
	Contract     *Message          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// MessageCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type MessageCallerSession struct {
	Contract *MessageCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// MessageTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type MessageTransactorSession struct {
	Contract     *MessageTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// MessageRaw is an auto generated low-level Go binding around an Ethereum contract.
type MessageRaw struct {
	Contract *Message // Generic contract binding to access the raw methods on
}

// MessageCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type MessageCallerRaw struct {
	Contract *MessageCaller // Generic read-only contract binding to access the raw methods on
}

// MessageTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type MessageTransactorRaw struct {
	Contract *MessageTransactor // Generic write-only contract binding to access the raw methods on
}

// NewMessage creates a new instance of Message, bound to a specific deployed contract.
func NewMessage(address common.Address, backend bind.ContractBackend) (*Message, error) {
	contract, err := bindMessage(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Message{MessageCaller: MessageCaller{contract: contract}, MessageTransactor: MessageTransactor{contract: contract}, MessageFilterer: MessageFilterer{contract: contract}}, nil
}

// NewMessageCaller creates a new read-only instance of Message, bound to a specific deployed contract.
func NewMessageCaller(address common.Address, caller bind.ContractCaller) (*MessageCaller, error) {
	contract, err := bindMessage(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &MessageCaller{contract: contract}, nil
}

// NewMessageTransactor creates a new write-only instance of Message, bound to a specific deployed contract.
func NewMessageTransactor(address common.Address, transactor bind.ContractTransactor) (*MessageTransactor, error) {
	contract, err := bindMessage(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &MessageTransactor{contract: contract}, nil
}

// NewMessageFilterer creates a new log filterer instance of Message, bound to a specific deployed contract.
func NewMessageFilterer(address common.Address, filterer bind.ContractFilterer) (*MessageFilterer, error) {
	contract, err := bindMessage(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &MessageFilterer{contract: contract}, nil
}

// bindMessage binds a generic wrapper to an already deployed contract.
func bindMessage(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(MessageABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Message *MessageRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Message.Contract.MessageCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Message *MessageRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Message.Contract.MessageTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Message *MessageRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Message.Contract.MessageTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Message *MessageCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Message.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Message *MessageTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Message.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Message *MessageTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Message.Contract.contract.Transact(opts, method, params...)
}

// OwnableUpgradeableMetaData contains all meta data concerning the OwnableUpgradeable contract.
var OwnableUpgradeableMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"8da5cb5b": "owner()",
		"715018a6": "renounceOwnership()",
		"f2fde38b": "transferOwnership(address)",
	},
}

// OwnableUpgradeableABI is the input ABI used to generate the binding from.
// Deprecated: Use OwnableUpgradeableMetaData.ABI instead.
var OwnableUpgradeableABI = OwnableUpgradeableMetaData.ABI

// Deprecated: Use OwnableUpgradeableMetaData.Sigs instead.
// OwnableUpgradeableFuncSigs maps the 4-byte function signature to its string representation.
var OwnableUpgradeableFuncSigs = OwnableUpgradeableMetaData.Sigs

// OwnableUpgradeable is an auto generated Go binding around an Ethereum contract.
type OwnableUpgradeable struct {
	OwnableUpgradeableCaller     // Read-only binding to the contract
	OwnableUpgradeableTransactor // Write-only binding to the contract
	OwnableUpgradeableFilterer   // Log filterer for contract events
}

// OwnableUpgradeableCaller is an auto generated read-only Go binding around an Ethereum contract.
type OwnableUpgradeableCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnableUpgradeableTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OwnableUpgradeableTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnableUpgradeableFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type OwnableUpgradeableFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OwnableUpgradeableSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OwnableUpgradeableSession struct {
	Contract     *OwnableUpgradeable // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// OwnableUpgradeableCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OwnableUpgradeableCallerSession struct {
	Contract *OwnableUpgradeableCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// OwnableUpgradeableTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OwnableUpgradeableTransactorSession struct {
	Contract     *OwnableUpgradeableTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// OwnableUpgradeableRaw is an auto generated low-level Go binding around an Ethereum contract.
type OwnableUpgradeableRaw struct {
	Contract *OwnableUpgradeable // Generic contract binding to access the raw methods on
}

// OwnableUpgradeableCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OwnableUpgradeableCallerRaw struct {
	Contract *OwnableUpgradeableCaller // Generic read-only contract binding to access the raw methods on
}

// OwnableUpgradeableTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OwnableUpgradeableTransactorRaw struct {
	Contract *OwnableUpgradeableTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOwnableUpgradeable creates a new instance of OwnableUpgradeable, bound to a specific deployed contract.
func NewOwnableUpgradeable(address common.Address, backend bind.ContractBackend) (*OwnableUpgradeable, error) {
	contract, err := bindOwnableUpgradeable(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &OwnableUpgradeable{OwnableUpgradeableCaller: OwnableUpgradeableCaller{contract: contract}, OwnableUpgradeableTransactor: OwnableUpgradeableTransactor{contract: contract}, OwnableUpgradeableFilterer: OwnableUpgradeableFilterer{contract: contract}}, nil
}

// NewOwnableUpgradeableCaller creates a new read-only instance of OwnableUpgradeable, bound to a specific deployed contract.
func NewOwnableUpgradeableCaller(address common.Address, caller bind.ContractCaller) (*OwnableUpgradeableCaller, error) {
	contract, err := bindOwnableUpgradeable(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &OwnableUpgradeableCaller{contract: contract}, nil
}

// NewOwnableUpgradeableTransactor creates a new write-only instance of OwnableUpgradeable, bound to a specific deployed contract.
func NewOwnableUpgradeableTransactor(address common.Address, transactor bind.ContractTransactor) (*OwnableUpgradeableTransactor, error) {
	contract, err := bindOwnableUpgradeable(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &OwnableUpgradeableTransactor{contract: contract}, nil
}

// NewOwnableUpgradeableFilterer creates a new log filterer instance of OwnableUpgradeable, bound to a specific deployed contract.
func NewOwnableUpgradeableFilterer(address common.Address, filterer bind.ContractFilterer) (*OwnableUpgradeableFilterer, error) {
	contract, err := bindOwnableUpgradeable(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &OwnableUpgradeableFilterer{contract: contract}, nil
}

// bindOwnableUpgradeable binds a generic wrapper to an already deployed contract.
func bindOwnableUpgradeable(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(OwnableUpgradeableABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OwnableUpgradeable *OwnableUpgradeableRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OwnableUpgradeable.Contract.OwnableUpgradeableCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OwnableUpgradeable *OwnableUpgradeableRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.OwnableUpgradeableTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OwnableUpgradeable *OwnableUpgradeableRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.OwnableUpgradeableTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OwnableUpgradeable *OwnableUpgradeableCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OwnableUpgradeable.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OwnableUpgradeable *OwnableUpgradeableTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OwnableUpgradeable *OwnableUpgradeableTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.contract.Transact(opts, method, params...)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_OwnableUpgradeable *OwnableUpgradeableCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _OwnableUpgradeable.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_OwnableUpgradeable *OwnableUpgradeableSession) Owner() (common.Address, error) {
	return _OwnableUpgradeable.Contract.Owner(&_OwnableUpgradeable.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_OwnableUpgradeable *OwnableUpgradeableCallerSession) Owner() (common.Address, error) {
	return _OwnableUpgradeable.Contract.Owner(&_OwnableUpgradeable.CallOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_OwnableUpgradeable *OwnableUpgradeableTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OwnableUpgradeable.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_OwnableUpgradeable *OwnableUpgradeableSession) RenounceOwnership() (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.RenounceOwnership(&_OwnableUpgradeable.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_OwnableUpgradeable *OwnableUpgradeableTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.RenounceOwnership(&_OwnableUpgradeable.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_OwnableUpgradeable *OwnableUpgradeableTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _OwnableUpgradeable.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_OwnableUpgradeable *OwnableUpgradeableSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.TransferOwnership(&_OwnableUpgradeable.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_OwnableUpgradeable *OwnableUpgradeableTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _OwnableUpgradeable.Contract.TransferOwnership(&_OwnableUpgradeable.TransactOpts, newOwner)
}

// OwnableUpgradeableInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the OwnableUpgradeable contract.
type OwnableUpgradeableInitializedIterator struct {
	Event *OwnableUpgradeableInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *OwnableUpgradeableInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(OwnableUpgradeableInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(OwnableUpgradeableInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *OwnableUpgradeableInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *OwnableUpgradeableInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// OwnableUpgradeableInitialized represents a Initialized event raised by the OwnableUpgradeable contract.
type OwnableUpgradeableInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_OwnableUpgradeable *OwnableUpgradeableFilterer) FilterInitialized(opts *bind.FilterOpts) (*OwnableUpgradeableInitializedIterator, error) {

	logs, sub, err := _OwnableUpgradeable.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &OwnableUpgradeableInitializedIterator{contract: _OwnableUpgradeable.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_OwnableUpgradeable *OwnableUpgradeableFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *OwnableUpgradeableInitialized) (event.Subscription, error) {

	logs, sub, err := _OwnableUpgradeable.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(OwnableUpgradeableInitialized)
				if err := _OwnableUpgradeable.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_OwnableUpgradeable *OwnableUpgradeableFilterer) ParseInitialized(log types.Log) (*OwnableUpgradeableInitialized, error) {
	event := new(OwnableUpgradeableInitialized)
	if err := _OwnableUpgradeable.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// OwnableUpgradeableOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the OwnableUpgradeable contract.
type OwnableUpgradeableOwnershipTransferredIterator struct {
	Event *OwnableUpgradeableOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *OwnableUpgradeableOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(OwnableUpgradeableOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(OwnableUpgradeableOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *OwnableUpgradeableOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *OwnableUpgradeableOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// OwnableUpgradeableOwnershipTransferred represents a OwnershipTransferred event raised by the OwnableUpgradeable contract.
type OwnableUpgradeableOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_OwnableUpgradeable *OwnableUpgradeableFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*OwnableUpgradeableOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _OwnableUpgradeable.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &OwnableUpgradeableOwnershipTransferredIterator{contract: _OwnableUpgradeable.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_OwnableUpgradeable *OwnableUpgradeableFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *OwnableUpgradeableOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _OwnableUpgradeable.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(OwnableUpgradeableOwnershipTransferred)
				if err := _OwnableUpgradeable.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_OwnableUpgradeable *OwnableUpgradeableFilterer) ParseOwnershipTransferred(log types.Log) (*OwnableUpgradeableOwnershipTransferred, error) {
	event := new(OwnableUpgradeableOwnershipTransferred)
	if err := _OwnableUpgradeable.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ReportMetaData contains all meta data concerning the Report contract.
var ReportMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea2646970667358221220f1a8e3a3e7c8e2bcd096305cf39bf16b09304e5a867662e76cd89495cdf7893964736f6c63430008110033",
}

// ReportABI is the input ABI used to generate the binding from.
// Deprecated: Use ReportMetaData.ABI instead.
var ReportABI = ReportMetaData.ABI

// ReportBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ReportMetaData.Bin instead.
var ReportBin = ReportMetaData.Bin

// DeployReport deploys a new Ethereum contract, binding an instance of Report to it.
func DeployReport(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Report, error) {
	parsed, err := ReportMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ReportBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Report{ReportCaller: ReportCaller{contract: contract}, ReportTransactor: ReportTransactor{contract: contract}, ReportFilterer: ReportFilterer{contract: contract}}, nil
}

// Report is an auto generated Go binding around an Ethereum contract.
type Report struct {
	ReportCaller     // Read-only binding to the contract
	ReportTransactor // Write-only binding to the contract
	ReportFilterer   // Log filterer for contract events
}

// ReportCaller is an auto generated read-only Go binding around an Ethereum contract.
type ReportCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ReportTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ReportTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ReportFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ReportFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ReportSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ReportSession struct {
	Contract     *Report           // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ReportCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ReportCallerSession struct {
	Contract *ReportCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// ReportTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ReportTransactorSession struct {
	Contract     *ReportTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ReportRaw is an auto generated low-level Go binding around an Ethereum contract.
type ReportRaw struct {
	Contract *Report // Generic contract binding to access the raw methods on
}

// ReportCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ReportCallerRaw struct {
	Contract *ReportCaller // Generic read-only contract binding to access the raw methods on
}

// ReportTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ReportTransactorRaw struct {
	Contract *ReportTransactor // Generic write-only contract binding to access the raw methods on
}

// NewReport creates a new instance of Report, bound to a specific deployed contract.
func NewReport(address common.Address, backend bind.ContractBackend) (*Report, error) {
	contract, err := bindReport(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Report{ReportCaller: ReportCaller{contract: contract}, ReportTransactor: ReportTransactor{contract: contract}, ReportFilterer: ReportFilterer{contract: contract}}, nil
}

// NewReportCaller creates a new read-only instance of Report, bound to a specific deployed contract.
func NewReportCaller(address common.Address, caller bind.ContractCaller) (*ReportCaller, error) {
	contract, err := bindReport(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ReportCaller{contract: contract}, nil
}

// NewReportTransactor creates a new write-only instance of Report, bound to a specific deployed contract.
func NewReportTransactor(address common.Address, transactor bind.ContractTransactor) (*ReportTransactor, error) {
	contract, err := bindReport(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ReportTransactor{contract: contract}, nil
}

// NewReportFilterer creates a new log filterer instance of Report, bound to a specific deployed contract.
func NewReportFilterer(address common.Address, filterer bind.ContractFilterer) (*ReportFilterer, error) {
	contract, err := bindReport(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ReportFilterer{contract: contract}, nil
}

// bindReport binds a generic wrapper to an already deployed contract.
func bindReport(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ReportABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Report *ReportRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Report.Contract.ReportCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Report *ReportRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Report.Contract.ReportTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Report *ReportRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Report.Contract.ReportTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Report *ReportCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Report.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Report *ReportTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Report.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Report *ReportTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Report.Contract.contract.Transact(opts, method, params...)
}

// ReportHubMetaData contains all meta data concerning the ReportHub contract.
var ReportHubMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"guards\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"address[]\",\"name\":\"notaries\",\"type\":\"address[]\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"attestation\",\"type\":\"bytes\"}],\"name\":\"AttestationAccepted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"allAgents\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"allDomains\",\"outputs\":[{\"internalType\":\"uint32[]\",\"name\":\"domains_\",\"type\":\"uint32[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"amountAgents\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"amountDomains\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"uint256\",\"name\":\"_agentIndex\",\"type\":\"uint256\"}],\"name\":\"getAgent\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_domainIndex\",\"type\":\"uint256\"}],\"name\":\"getDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"isActiveDomain\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_attestation\",\"type\":\"bytes\"}],\"name\":\"submitAttestation\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_report\",\"type\":\"bytes\"}],\"name\":\"submitReport\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"64ecb518": "allAgents(uint32)",
		"6f225878": "allDomains()",
		"32254098": "amountAgents(uint32)",
		"61b0b357": "amountDomains()",
		"1d82873b": "getAgent(uint32,uint256)",
		"1a7a98e2": "getDomain(uint256)",
		"65e1e466": "isActiveAgent(address)",
		"0958117d": "isActiveAgent(uint32,address)",
		"4f5dbc0d": "isActiveDomain(uint32)",
		"f646a512": "submitAttestation(bytes)",
		"5815869d": "submitReport(bytes)",
	},
}

// ReportHubABI is the input ABI used to generate the binding from.
// Deprecated: Use ReportHubMetaData.ABI instead.
var ReportHubABI = ReportHubMetaData.ABI

// Deprecated: Use ReportHubMetaData.Sigs instead.
// ReportHubFuncSigs maps the 4-byte function signature to its string representation.
var ReportHubFuncSigs = ReportHubMetaData.Sigs

// ReportHub is an auto generated Go binding around an Ethereum contract.
type ReportHub struct {
	ReportHubCaller     // Read-only binding to the contract
	ReportHubTransactor // Write-only binding to the contract
	ReportHubFilterer   // Log filterer for contract events
}

// ReportHubCaller is an auto generated read-only Go binding around an Ethereum contract.
type ReportHubCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ReportHubTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ReportHubTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ReportHubFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ReportHubFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ReportHubSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ReportHubSession struct {
	Contract     *ReportHub        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ReportHubCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ReportHubCallerSession struct {
	Contract *ReportHubCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// ReportHubTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ReportHubTransactorSession struct {
	Contract     *ReportHubTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// ReportHubRaw is an auto generated low-level Go binding around an Ethereum contract.
type ReportHubRaw struct {
	Contract *ReportHub // Generic contract binding to access the raw methods on
}

// ReportHubCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ReportHubCallerRaw struct {
	Contract *ReportHubCaller // Generic read-only contract binding to access the raw methods on
}

// ReportHubTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ReportHubTransactorRaw struct {
	Contract *ReportHubTransactor // Generic write-only contract binding to access the raw methods on
}

// NewReportHub creates a new instance of ReportHub, bound to a specific deployed contract.
func NewReportHub(address common.Address, backend bind.ContractBackend) (*ReportHub, error) {
	contract, err := bindReportHub(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ReportHub{ReportHubCaller: ReportHubCaller{contract: contract}, ReportHubTransactor: ReportHubTransactor{contract: contract}, ReportHubFilterer: ReportHubFilterer{contract: contract}}, nil
}

// NewReportHubCaller creates a new read-only instance of ReportHub, bound to a specific deployed contract.
func NewReportHubCaller(address common.Address, caller bind.ContractCaller) (*ReportHubCaller, error) {
	contract, err := bindReportHub(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ReportHubCaller{contract: contract}, nil
}

// NewReportHubTransactor creates a new write-only instance of ReportHub, bound to a specific deployed contract.
func NewReportHubTransactor(address common.Address, transactor bind.ContractTransactor) (*ReportHubTransactor, error) {
	contract, err := bindReportHub(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ReportHubTransactor{contract: contract}, nil
}

// NewReportHubFilterer creates a new log filterer instance of ReportHub, bound to a specific deployed contract.
func NewReportHubFilterer(address common.Address, filterer bind.ContractFilterer) (*ReportHubFilterer, error) {
	contract, err := bindReportHub(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ReportHubFilterer{contract: contract}, nil
}

// bindReportHub binds a generic wrapper to an already deployed contract.
func bindReportHub(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ReportHubABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ReportHub *ReportHubRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ReportHub.Contract.ReportHubCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ReportHub *ReportHubRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ReportHub.Contract.ReportHubTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ReportHub *ReportHubRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ReportHub.Contract.ReportHubTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ReportHub *ReportHubCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ReportHub.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ReportHub *ReportHubTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ReportHub.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ReportHub *ReportHubTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ReportHub.Contract.contract.Transact(opts, method, params...)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_ReportHub *ReportHubCaller) AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "allAgents", _domain)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_ReportHub *ReportHubSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _ReportHub.Contract.AllAgents(&_ReportHub.CallOpts, _domain)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_ReportHub *ReportHubCallerSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _ReportHub.Contract.AllAgents(&_ReportHub.CallOpts, _domain)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_ReportHub *ReportHubCaller) AllDomains(opts *bind.CallOpts) ([]uint32, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "allDomains")

	if err != nil {
		return *new([]uint32), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint32)).(*[]uint32)

	return out0, err

}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_ReportHub *ReportHubSession) AllDomains() ([]uint32, error) {
	return _ReportHub.Contract.AllDomains(&_ReportHub.CallOpts)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_ReportHub *ReportHubCallerSession) AllDomains() ([]uint32, error) {
	return _ReportHub.Contract.AllDomains(&_ReportHub.CallOpts)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_ReportHub *ReportHubCaller) AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "amountAgents", _domain)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_ReportHub *ReportHubSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _ReportHub.Contract.AmountAgents(&_ReportHub.CallOpts, _domain)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_ReportHub *ReportHubCallerSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _ReportHub.Contract.AmountAgents(&_ReportHub.CallOpts, _domain)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_ReportHub *ReportHubCaller) AmountDomains(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "amountDomains")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_ReportHub *ReportHubSession) AmountDomains() (*big.Int, error) {
	return _ReportHub.Contract.AmountDomains(&_ReportHub.CallOpts)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_ReportHub *ReportHubCallerSession) AmountDomains() (*big.Int, error) {
	return _ReportHub.Contract.AmountDomains(&_ReportHub.CallOpts)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_ReportHub *ReportHubCaller) GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "getAgent", _domain, _agentIndex)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_ReportHub *ReportHubSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _ReportHub.Contract.GetAgent(&_ReportHub.CallOpts, _domain, _agentIndex)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_ReportHub *ReportHubCallerSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _ReportHub.Contract.GetAgent(&_ReportHub.CallOpts, _domain, _agentIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_ReportHub *ReportHubCaller) GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "getDomain", _domainIndex)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_ReportHub *ReportHubSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _ReportHub.Contract.GetDomain(&_ReportHub.CallOpts, _domainIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_ReportHub *ReportHubCallerSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _ReportHub.Contract.GetDomain(&_ReportHub.CallOpts, _domainIndex)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_ReportHub *ReportHubCaller) IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "isActiveAgent", _domain, _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_ReportHub *ReportHubSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _ReportHub.Contract.IsActiveAgent(&_ReportHub.CallOpts, _domain, _account)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_ReportHub *ReportHubCallerSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _ReportHub.Contract.IsActiveAgent(&_ReportHub.CallOpts, _domain, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_ReportHub *ReportHubCaller) IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "isActiveAgent0", _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_ReportHub *ReportHubSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _ReportHub.Contract.IsActiveAgent0(&_ReportHub.CallOpts, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_ReportHub *ReportHubCallerSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _ReportHub.Contract.IsActiveAgent0(&_ReportHub.CallOpts, _account)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_ReportHub *ReportHubCaller) IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error) {
	var out []interface{}
	err := _ReportHub.contract.Call(opts, &out, "isActiveDomain", _domain)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_ReportHub *ReportHubSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _ReportHub.Contract.IsActiveDomain(&_ReportHub.CallOpts, _domain)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_ReportHub *ReportHubCallerSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _ReportHub.Contract.IsActiveDomain(&_ReportHub.CallOpts, _domain)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_ReportHub *ReportHubTransactor) SubmitAttestation(opts *bind.TransactOpts, _attestation []byte) (*types.Transaction, error) {
	return _ReportHub.contract.Transact(opts, "submitAttestation", _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_ReportHub *ReportHubSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _ReportHub.Contract.SubmitAttestation(&_ReportHub.TransactOpts, _attestation)
}

// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
//
// Solidity: function submitAttestation(bytes _attestation) returns(bool)
func (_ReportHub *ReportHubTransactorSession) SubmitAttestation(_attestation []byte) (*types.Transaction, error) {
	return _ReportHub.Contract.SubmitAttestation(&_ReportHub.TransactOpts, _attestation)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_ReportHub *ReportHubTransactor) SubmitReport(opts *bind.TransactOpts, _report []byte) (*types.Transaction, error) {
	return _ReportHub.contract.Transact(opts, "submitReport", _report)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_ReportHub *ReportHubSession) SubmitReport(_report []byte) (*types.Transaction, error) {
	return _ReportHub.Contract.SubmitReport(&_ReportHub.TransactOpts, _report)
}

// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
//
// Solidity: function submitReport(bytes _report) returns(bool)
func (_ReportHub *ReportHubTransactorSession) SubmitReport(_report []byte) (*types.Transaction, error) {
	return _ReportHub.Contract.SubmitReport(&_ReportHub.TransactOpts, _report)
}

// ReportHubAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the ReportHub contract.
type ReportHubAgentAddedIterator struct {
	Event *ReportHubAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ReportHubAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ReportHubAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ReportHubAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ReportHubAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ReportHubAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ReportHubAgentAdded represents a AgentAdded event raised by the ReportHub contract.
type ReportHubAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_ReportHub *ReportHubFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*ReportHubAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _ReportHub.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &ReportHubAgentAddedIterator{contract: _ReportHub.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_ReportHub *ReportHubFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *ReportHubAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _ReportHub.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ReportHubAgentAdded)
				if err := _ReportHub.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_ReportHub *ReportHubFilterer) ParseAgentAdded(log types.Log) (*ReportHubAgentAdded, error) {
	event := new(ReportHubAgentAdded)
	if err := _ReportHub.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ReportHubAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the ReportHub contract.
type ReportHubAgentRemovedIterator struct {
	Event *ReportHubAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ReportHubAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ReportHubAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ReportHubAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ReportHubAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ReportHubAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ReportHubAgentRemoved represents a AgentRemoved event raised by the ReportHub contract.
type ReportHubAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_ReportHub *ReportHubFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*ReportHubAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _ReportHub.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &ReportHubAgentRemovedIterator{contract: _ReportHub.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_ReportHub *ReportHubFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *ReportHubAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _ReportHub.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ReportHubAgentRemoved)
				if err := _ReportHub.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_ReportHub *ReportHubFilterer) ParseAgentRemoved(log types.Log) (*ReportHubAgentRemoved, error) {
	event := new(ReportHubAgentRemoved)
	if err := _ReportHub.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ReportHubAttestationAcceptedIterator is returned from FilterAttestationAccepted and is used to iterate over the raw logs and unpacked data for AttestationAccepted events raised by the ReportHub contract.
type ReportHubAttestationAcceptedIterator struct {
	Event *ReportHubAttestationAccepted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ReportHubAttestationAcceptedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ReportHubAttestationAccepted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ReportHubAttestationAccepted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ReportHubAttestationAcceptedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ReportHubAttestationAcceptedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ReportHubAttestationAccepted represents a AttestationAccepted event raised by the ReportHub contract.
type ReportHubAttestationAccepted struct {
	Guards      []common.Address
	Notaries    []common.Address
	Attestation []byte
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterAttestationAccepted is a free log retrieval operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_ReportHub *ReportHubFilterer) FilterAttestationAccepted(opts *bind.FilterOpts) (*ReportHubAttestationAcceptedIterator, error) {

	logs, sub, err := _ReportHub.contract.FilterLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return &ReportHubAttestationAcceptedIterator{contract: _ReportHub.contract, event: "AttestationAccepted", logs: logs, sub: sub}, nil
}

// WatchAttestationAccepted is a free log subscription operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_ReportHub *ReportHubFilterer) WatchAttestationAccepted(opts *bind.WatchOpts, sink chan<- *ReportHubAttestationAccepted) (event.Subscription, error) {

	logs, sub, err := _ReportHub.contract.WatchLogs(opts, "AttestationAccepted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ReportHubAttestationAccepted)
				if err := _ReportHub.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAttestationAccepted is a log parse operation binding the contract event 0x4f0c90de207e0a470e5e1f82afac401eb563d4f550ffeabf940201329fc2bba0.
//
// Solidity: event AttestationAccepted(address[] guards, address[] notaries, bytes attestation)
func (_ReportHub *ReportHubFilterer) ParseAttestationAccepted(log types.Log) (*ReportHubAttestationAccepted, error) {
	event := new(ReportHubAttestationAccepted)
	if err := _ReportHub.contract.UnpackLog(event, "AttestationAccepted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ReportHubDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the ReportHub contract.
type ReportHubDomainActivatedIterator struct {
	Event *ReportHubDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ReportHubDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ReportHubDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ReportHubDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ReportHubDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ReportHubDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ReportHubDomainActivated represents a DomainActivated event raised by the ReportHub contract.
type ReportHubDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_ReportHub *ReportHubFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*ReportHubDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _ReportHub.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &ReportHubDomainActivatedIterator{contract: _ReportHub.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_ReportHub *ReportHubFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *ReportHubDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _ReportHub.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ReportHubDomainActivated)
				if err := _ReportHub.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_ReportHub *ReportHubFilterer) ParseDomainActivated(log types.Log) (*ReportHubDomainActivated, error) {
	event := new(ReportHubDomainActivated)
	if err := _ReportHub.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ReportHubDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the ReportHub contract.
type ReportHubDomainDeactivatedIterator struct {
	Event *ReportHubDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ReportHubDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ReportHubDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ReportHubDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ReportHubDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ReportHubDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ReportHubDomainDeactivated represents a DomainDeactivated event raised by the ReportHub contract.
type ReportHubDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_ReportHub *ReportHubFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*ReportHubDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _ReportHub.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &ReportHubDomainDeactivatedIterator{contract: _ReportHub.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_ReportHub *ReportHubFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *ReportHubDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _ReportHub.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ReportHubDomainDeactivated)
				if err := _ReportHub.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_ReportHub *ReportHubFilterer) ParseDomainDeactivated(log types.Log) (*ReportHubDomainDeactivated, error) {
	event := new(ReportHubDomainDeactivated)
	if err := _ReportHub.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StringsMetaData contains all meta data concerning the Strings contract.
var StringsMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea26469706673582212208d6c96b0ab3f449e3166c925f4529ac6e749effb6c37b4c91478bb53f446523264736f6c63430008110033",
}

// StringsABI is the input ABI used to generate the binding from.
// Deprecated: Use StringsMetaData.ABI instead.
var StringsABI = StringsMetaData.ABI

// StringsBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use StringsMetaData.Bin instead.
var StringsBin = StringsMetaData.Bin

// DeployStrings deploys a new Ethereum contract, binding an instance of Strings to it.
func DeployStrings(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Strings, error) {
	parsed, err := StringsMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(StringsBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Strings{StringsCaller: StringsCaller{contract: contract}, StringsTransactor: StringsTransactor{contract: contract}, StringsFilterer: StringsFilterer{contract: contract}}, nil
}

// Strings is an auto generated Go binding around an Ethereum contract.
type Strings struct {
	StringsCaller     // Read-only binding to the contract
	StringsTransactor // Write-only binding to the contract
	StringsFilterer   // Log filterer for contract events
}

// StringsCaller is an auto generated read-only Go binding around an Ethereum contract.
type StringsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StringsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type StringsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StringsFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type StringsFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StringsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type StringsSession struct {
	Contract     *Strings          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// StringsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type StringsCallerSession struct {
	Contract *StringsCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// StringsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type StringsTransactorSession struct {
	Contract     *StringsTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// StringsRaw is an auto generated low-level Go binding around an Ethereum contract.
type StringsRaw struct {
	Contract *Strings // Generic contract binding to access the raw methods on
}

// StringsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type StringsCallerRaw struct {
	Contract *StringsCaller // Generic read-only contract binding to access the raw methods on
}

// StringsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type StringsTransactorRaw struct {
	Contract *StringsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewStrings creates a new instance of Strings, bound to a specific deployed contract.
func NewStrings(address common.Address, backend bind.ContractBackend) (*Strings, error) {
	contract, err := bindStrings(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Strings{StringsCaller: StringsCaller{contract: contract}, StringsTransactor: StringsTransactor{contract: contract}, StringsFilterer: StringsFilterer{contract: contract}}, nil
}

// NewStringsCaller creates a new read-only instance of Strings, bound to a specific deployed contract.
func NewStringsCaller(address common.Address, caller bind.ContractCaller) (*StringsCaller, error) {
	contract, err := bindStrings(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &StringsCaller{contract: contract}, nil
}

// NewStringsTransactor creates a new write-only instance of Strings, bound to a specific deployed contract.
func NewStringsTransactor(address common.Address, transactor bind.ContractTransactor) (*StringsTransactor, error) {
	contract, err := bindStrings(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &StringsTransactor{contract: contract}, nil
}

// NewStringsFilterer creates a new log filterer instance of Strings, bound to a specific deployed contract.
func NewStringsFilterer(address common.Address, filterer bind.ContractFilterer) (*StringsFilterer, error) {
	contract, err := bindStrings(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &StringsFilterer{contract: contract}, nil
}

// bindStrings binds a generic wrapper to an already deployed contract.
func bindStrings(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(StringsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Strings *StringsRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Strings.Contract.StringsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Strings *StringsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Strings.Contract.StringsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Strings *StringsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Strings.Contract.StringsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Strings *StringsCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Strings.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Strings *StringsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Strings.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Strings *StringsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Strings.Contract.contract.Transact(opts, method, params...)
}

// SynapseTypesMetaData contains all meta data concerning the SynapseTypes contract.
var SynapseTypesMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122043b9d9a60d56a118c0b831ff6709cc7419c5e738f2587b620c425ce87cedf46664736f6c63430008110033",
}

// SynapseTypesABI is the input ABI used to generate the binding from.
// Deprecated: Use SynapseTypesMetaData.ABI instead.
var SynapseTypesABI = SynapseTypesMetaData.ABI

// SynapseTypesBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use SynapseTypesMetaData.Bin instead.
var SynapseTypesBin = SynapseTypesMetaData.Bin

// DeploySynapseTypes deploys a new Ethereum contract, binding an instance of SynapseTypes to it.
func DeploySynapseTypes(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *SynapseTypes, error) {
	parsed, err := SynapseTypesMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(SynapseTypesBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SynapseTypes{SynapseTypesCaller: SynapseTypesCaller{contract: contract}, SynapseTypesTransactor: SynapseTypesTransactor{contract: contract}, SynapseTypesFilterer: SynapseTypesFilterer{contract: contract}}, nil
}

// SynapseTypes is an auto generated Go binding around an Ethereum contract.
type SynapseTypes struct {
	SynapseTypesCaller     // Read-only binding to the contract
	SynapseTypesTransactor // Write-only binding to the contract
	SynapseTypesFilterer   // Log filterer for contract events
}

// SynapseTypesCaller is an auto generated read-only Go binding around an Ethereum contract.
type SynapseTypesCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SynapseTypesTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SynapseTypesTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SynapseTypesFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SynapseTypesFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SynapseTypesSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SynapseTypesSession struct {
	Contract     *SynapseTypes     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SynapseTypesCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SynapseTypesCallerSession struct {
	Contract *SynapseTypesCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// SynapseTypesTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SynapseTypesTransactorSession struct {
	Contract     *SynapseTypesTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// SynapseTypesRaw is an auto generated low-level Go binding around an Ethereum contract.
type SynapseTypesRaw struct {
	Contract *SynapseTypes // Generic contract binding to access the raw methods on
}

// SynapseTypesCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SynapseTypesCallerRaw struct {
	Contract *SynapseTypesCaller // Generic read-only contract binding to access the raw methods on
}

// SynapseTypesTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SynapseTypesTransactorRaw struct {
	Contract *SynapseTypesTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSynapseTypes creates a new instance of SynapseTypes, bound to a specific deployed contract.
func NewSynapseTypes(address common.Address, backend bind.ContractBackend) (*SynapseTypes, error) {
	contract, err := bindSynapseTypes(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SynapseTypes{SynapseTypesCaller: SynapseTypesCaller{contract: contract}, SynapseTypesTransactor: SynapseTypesTransactor{contract: contract}, SynapseTypesFilterer: SynapseTypesFilterer{contract: contract}}, nil
}

// NewSynapseTypesCaller creates a new read-only instance of SynapseTypes, bound to a specific deployed contract.
func NewSynapseTypesCaller(address common.Address, caller bind.ContractCaller) (*SynapseTypesCaller, error) {
	contract, err := bindSynapseTypes(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SynapseTypesCaller{contract: contract}, nil
}

// NewSynapseTypesTransactor creates a new write-only instance of SynapseTypes, bound to a specific deployed contract.
func NewSynapseTypesTransactor(address common.Address, transactor bind.ContractTransactor) (*SynapseTypesTransactor, error) {
	contract, err := bindSynapseTypes(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SynapseTypesTransactor{contract: contract}, nil
}

// NewSynapseTypesFilterer creates a new log filterer instance of SynapseTypes, bound to a specific deployed contract.
func NewSynapseTypesFilterer(address common.Address, filterer bind.ContractFilterer) (*SynapseTypesFilterer, error) {
	contract, err := bindSynapseTypes(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SynapseTypesFilterer{contract: contract}, nil
}

// bindSynapseTypes binds a generic wrapper to an already deployed contract.
func bindSynapseTypes(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(SynapseTypesABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SynapseTypes *SynapseTypesRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SynapseTypes.Contract.SynapseTypesCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SynapseTypes *SynapseTypesRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SynapseTypes.Contract.SynapseTypesTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SynapseTypes *SynapseTypesRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SynapseTypes.Contract.SynapseTypesTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SynapseTypes *SynapseTypesCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SynapseTypes.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SynapseTypes *SynapseTypesTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SynapseTypes.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SynapseTypes *SynapseTypesTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SynapseTypes.Contract.contract.Transact(opts, method, params...)
}

// SystemCallMetaData contains all meta data concerning the SystemCall contract.
var SystemCallMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122011c87facb7e6b69f2b0177ecc22801100a5d1827fabcc6a3eacc0f74dd3c376164736f6c63430008110033",
}

// SystemCallABI is the input ABI used to generate the binding from.
// Deprecated: Use SystemCallMetaData.ABI instead.
var SystemCallABI = SystemCallMetaData.ABI

// SystemCallBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use SystemCallMetaData.Bin instead.
var SystemCallBin = SystemCallMetaData.Bin

// DeploySystemCall deploys a new Ethereum contract, binding an instance of SystemCall to it.
func DeploySystemCall(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *SystemCall, error) {
	parsed, err := SystemCallMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(SystemCallBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SystemCall{SystemCallCaller: SystemCallCaller{contract: contract}, SystemCallTransactor: SystemCallTransactor{contract: contract}, SystemCallFilterer: SystemCallFilterer{contract: contract}}, nil
}

// SystemCall is an auto generated Go binding around an Ethereum contract.
type SystemCall struct {
	SystemCallCaller     // Read-only binding to the contract
	SystemCallTransactor // Write-only binding to the contract
	SystemCallFilterer   // Log filterer for contract events
}

// SystemCallCaller is an auto generated read-only Go binding around an Ethereum contract.
type SystemCallCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemCallTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SystemCallTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemCallFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SystemCallFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemCallSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SystemCallSession struct {
	Contract     *SystemCall       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SystemCallCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SystemCallCallerSession struct {
	Contract *SystemCallCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// SystemCallTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SystemCallTransactorSession struct {
	Contract     *SystemCallTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// SystemCallRaw is an auto generated low-level Go binding around an Ethereum contract.
type SystemCallRaw struct {
	Contract *SystemCall // Generic contract binding to access the raw methods on
}

// SystemCallCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SystemCallCallerRaw struct {
	Contract *SystemCallCaller // Generic read-only contract binding to access the raw methods on
}

// SystemCallTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SystemCallTransactorRaw struct {
	Contract *SystemCallTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSystemCall creates a new instance of SystemCall, bound to a specific deployed contract.
func NewSystemCall(address common.Address, backend bind.ContractBackend) (*SystemCall, error) {
	contract, err := bindSystemCall(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SystemCall{SystemCallCaller: SystemCallCaller{contract: contract}, SystemCallTransactor: SystemCallTransactor{contract: contract}, SystemCallFilterer: SystemCallFilterer{contract: contract}}, nil
}

// NewSystemCallCaller creates a new read-only instance of SystemCall, bound to a specific deployed contract.
func NewSystemCallCaller(address common.Address, caller bind.ContractCaller) (*SystemCallCaller, error) {
	contract, err := bindSystemCall(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SystemCallCaller{contract: contract}, nil
}

// NewSystemCallTransactor creates a new write-only instance of SystemCall, bound to a specific deployed contract.
func NewSystemCallTransactor(address common.Address, transactor bind.ContractTransactor) (*SystemCallTransactor, error) {
	contract, err := bindSystemCall(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SystemCallTransactor{contract: contract}, nil
}

// NewSystemCallFilterer creates a new log filterer instance of SystemCall, bound to a specific deployed contract.
func NewSystemCallFilterer(address common.Address, filterer bind.ContractFilterer) (*SystemCallFilterer, error) {
	contract, err := bindSystemCall(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SystemCallFilterer{contract: contract}, nil
}

// bindSystemCall binds a generic wrapper to an already deployed contract.
func bindSystemCall(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(SystemCallABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SystemCall *SystemCallRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SystemCall.Contract.SystemCallCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SystemCall *SystemCallRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemCall.Contract.SystemCallTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SystemCall *SystemCallRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SystemCall.Contract.SystemCallTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SystemCall *SystemCallCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SystemCall.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SystemCall *SystemCallTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemCall.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SystemCall *SystemCallTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SystemCall.Contract.contract.Transact(opts, method, params...)
}

// SystemContractMetaData contains all meta data concerning the SystemContract contract.
var SystemContractMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"SYNAPSE_DOMAIN\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"localDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"_systemRouter\",\"type\":\"address\"}],\"name\":\"setSystemRouter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_rootSubmittedAt\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo\",\"name\":\"_info\",\"type\":\"tuple\"}],\"name\":\"slashAgent\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_rootSubmittedAt\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_requestID\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"_removeExisting\",\"type\":\"bool\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo[]\",\"name\":\"_infos\",\"type\":\"tuple[]\"}],\"name\":\"syncAgents\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"systemRouter\",\"outputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"bf61e67e": "SYNAPSE_DOMAIN()",
		"8d3638f4": "localDomain()",
		"8da5cb5b": "owner()",
		"715018a6": "renounceOwnership()",
		"fbde22f7": "setSystemRouter(address)",
		"31f36451": "slashAgent(uint256,uint32,uint8,(uint32,address,bool))",
		"cc118b4d": "syncAgents(uint256,uint32,uint8,uint256,bool,(uint32,address,bool)[])",
		"529d1549": "systemRouter()",
		"f2fde38b": "transferOwnership(address)",
	},
}

// SystemContractABI is the input ABI used to generate the binding from.
// Deprecated: Use SystemContractMetaData.ABI instead.
var SystemContractABI = SystemContractMetaData.ABI

// Deprecated: Use SystemContractMetaData.Sigs instead.
// SystemContractFuncSigs maps the 4-byte function signature to its string representation.
var SystemContractFuncSigs = SystemContractMetaData.Sigs

// SystemContract is an auto generated Go binding around an Ethereum contract.
type SystemContract struct {
	SystemContractCaller     // Read-only binding to the contract
	SystemContractTransactor // Write-only binding to the contract
	SystemContractFilterer   // Log filterer for contract events
}

// SystemContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type SystemContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SystemContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SystemContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SystemContractSession struct {
	Contract     *SystemContract   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SystemContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SystemContractCallerSession struct {
	Contract *SystemContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// SystemContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SystemContractTransactorSession struct {
	Contract     *SystemContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// SystemContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type SystemContractRaw struct {
	Contract *SystemContract // Generic contract binding to access the raw methods on
}

// SystemContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SystemContractCallerRaw struct {
	Contract *SystemContractCaller // Generic read-only contract binding to access the raw methods on
}

// SystemContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SystemContractTransactorRaw struct {
	Contract *SystemContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSystemContract creates a new instance of SystemContract, bound to a specific deployed contract.
func NewSystemContract(address common.Address, backend bind.ContractBackend) (*SystemContract, error) {
	contract, err := bindSystemContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SystemContract{SystemContractCaller: SystemContractCaller{contract: contract}, SystemContractTransactor: SystemContractTransactor{contract: contract}, SystemContractFilterer: SystemContractFilterer{contract: contract}}, nil
}

// NewSystemContractCaller creates a new read-only instance of SystemContract, bound to a specific deployed contract.
func NewSystemContractCaller(address common.Address, caller bind.ContractCaller) (*SystemContractCaller, error) {
	contract, err := bindSystemContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SystemContractCaller{contract: contract}, nil
}

// NewSystemContractTransactor creates a new write-only instance of SystemContract, bound to a specific deployed contract.
func NewSystemContractTransactor(address common.Address, transactor bind.ContractTransactor) (*SystemContractTransactor, error) {
	contract, err := bindSystemContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SystemContractTransactor{contract: contract}, nil
}

// NewSystemContractFilterer creates a new log filterer instance of SystemContract, bound to a specific deployed contract.
func NewSystemContractFilterer(address common.Address, filterer bind.ContractFilterer) (*SystemContractFilterer, error) {
	contract, err := bindSystemContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SystemContractFilterer{contract: contract}, nil
}

// bindSystemContract binds a generic wrapper to an already deployed contract.
func bindSystemContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(SystemContractABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SystemContract *SystemContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SystemContract.Contract.SystemContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SystemContract *SystemContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemContract.Contract.SystemContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SystemContract *SystemContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SystemContract.Contract.SystemContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SystemContract *SystemContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SystemContract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SystemContract *SystemContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemContract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SystemContract *SystemContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SystemContract.Contract.contract.Transact(opts, method, params...)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_SystemContract *SystemContractCaller) SYNAPSEDOMAIN(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _SystemContract.contract.Call(opts, &out, "SYNAPSE_DOMAIN")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_SystemContract *SystemContractSession) SYNAPSEDOMAIN() (uint32, error) {
	return _SystemContract.Contract.SYNAPSEDOMAIN(&_SystemContract.CallOpts)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_SystemContract *SystemContractCallerSession) SYNAPSEDOMAIN() (uint32, error) {
	return _SystemContract.Contract.SYNAPSEDOMAIN(&_SystemContract.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_SystemContract *SystemContractCaller) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _SystemContract.contract.Call(opts, &out, "localDomain")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_SystemContract *SystemContractSession) LocalDomain() (uint32, error) {
	return _SystemContract.Contract.LocalDomain(&_SystemContract.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_SystemContract *SystemContractCallerSession) LocalDomain() (uint32, error) {
	return _SystemContract.Contract.LocalDomain(&_SystemContract.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SystemContract *SystemContractCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SystemContract.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SystemContract *SystemContractSession) Owner() (common.Address, error) {
	return _SystemContract.Contract.Owner(&_SystemContract.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SystemContract *SystemContractCallerSession) Owner() (common.Address, error) {
	return _SystemContract.Contract.Owner(&_SystemContract.CallOpts)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_SystemContract *SystemContractCaller) SystemRouter(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SystemContract.contract.Call(opts, &out, "systemRouter")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_SystemContract *SystemContractSession) SystemRouter() (common.Address, error) {
	return _SystemContract.Contract.SystemRouter(&_SystemContract.CallOpts)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_SystemContract *SystemContractCallerSession) SystemRouter() (common.Address, error) {
	return _SystemContract.Contract.SystemRouter(&_SystemContract.CallOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SystemContract *SystemContractTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemContract.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SystemContract *SystemContractSession) RenounceOwnership() (*types.Transaction, error) {
	return _SystemContract.Contract.RenounceOwnership(&_SystemContract.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SystemContract *SystemContractTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _SystemContract.Contract.RenounceOwnership(&_SystemContract.TransactOpts)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_SystemContract *SystemContractTransactor) SetSystemRouter(opts *bind.TransactOpts, _systemRouter common.Address) (*types.Transaction, error) {
	return _SystemContract.contract.Transact(opts, "setSystemRouter", _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_SystemContract *SystemContractSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _SystemContract.Contract.SetSystemRouter(&_SystemContract.TransactOpts, _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_SystemContract *SystemContractTransactorSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _SystemContract.Contract.SetSystemRouter(&_SystemContract.TransactOpts, _systemRouter)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 _rootSubmittedAt, uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_SystemContract *SystemContractTransactor) SlashAgent(opts *bind.TransactOpts, _rootSubmittedAt *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemContract.contract.Transact(opts, "slashAgent", _rootSubmittedAt, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 _rootSubmittedAt, uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_SystemContract *SystemContractSession) SlashAgent(_rootSubmittedAt *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemContract.Contract.SlashAgent(&_SystemContract.TransactOpts, _rootSubmittedAt, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 _rootSubmittedAt, uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_SystemContract *SystemContractTransactorSession) SlashAgent(_rootSubmittedAt *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemContract.Contract.SlashAgent(&_SystemContract.TransactOpts, _rootSubmittedAt, _callOrigin, _caller, _info)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 _rootSubmittedAt, uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_SystemContract *SystemContractTransactor) SyncAgents(opts *bind.TransactOpts, _rootSubmittedAt *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemContract.contract.Transact(opts, "syncAgents", _rootSubmittedAt, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 _rootSubmittedAt, uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_SystemContract *SystemContractSession) SyncAgents(_rootSubmittedAt *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemContract.Contract.SyncAgents(&_SystemContract.TransactOpts, _rootSubmittedAt, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 _rootSubmittedAt, uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_SystemContract *SystemContractTransactorSession) SyncAgents(_rootSubmittedAt *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemContract.Contract.SyncAgents(&_SystemContract.TransactOpts, _rootSubmittedAt, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SystemContract *SystemContractTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _SystemContract.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SystemContract *SystemContractSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SystemContract.Contract.TransferOwnership(&_SystemContract.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SystemContract *SystemContractTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SystemContract.Contract.TransferOwnership(&_SystemContract.TransactOpts, newOwner)
}

// SystemContractInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the SystemContract contract.
type SystemContractInitializedIterator struct {
	Event *SystemContractInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemContractInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemContractInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemContractInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemContractInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemContractInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemContractInitialized represents a Initialized event raised by the SystemContract contract.
type SystemContractInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_SystemContract *SystemContractFilterer) FilterInitialized(opts *bind.FilterOpts) (*SystemContractInitializedIterator, error) {

	logs, sub, err := _SystemContract.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &SystemContractInitializedIterator{contract: _SystemContract.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_SystemContract *SystemContractFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *SystemContractInitialized) (event.Subscription, error) {

	logs, sub, err := _SystemContract.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemContractInitialized)
				if err := _SystemContract.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_SystemContract *SystemContractFilterer) ParseInitialized(log types.Log) (*SystemContractInitialized, error) {
	event := new(SystemContractInitialized)
	if err := _SystemContract.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemContractOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the SystemContract contract.
type SystemContractOwnershipTransferredIterator struct {
	Event *SystemContractOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemContractOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemContractOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemContractOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemContractOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemContractOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemContractOwnershipTransferred represents a OwnershipTransferred event raised by the SystemContract contract.
type SystemContractOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SystemContract *SystemContractFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*SystemContractOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SystemContract.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SystemContractOwnershipTransferredIterator{contract: _SystemContract.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SystemContract *SystemContractFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *SystemContractOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SystemContract.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemContractOwnershipTransferred)
				if err := _SystemContract.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SystemContract *SystemContractFilterer) ParseOwnershipTransferred(log types.Log) (*SystemContractOwnershipTransferred, error) {
	event := new(SystemContractOwnershipTransferred)
	if err := _SystemContract.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemRegistryMetaData contains all meta data concerning the SystemRegistry contract.
var SystemRegistryMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"AgentRemoved\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainActivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"}],\"name\":\"DomainDeactivated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"version\",\"type\":\"uint8\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"SYNAPSE_DOMAIN\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"allAgents\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"allDomains\",\"outputs\":[{\"internalType\":\"uint32[]\",\"name\":\"domains_\",\"type\":\"uint32[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"amountAgents\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"amountDomains\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"uint256\",\"name\":\"_agentIndex\",\"type\":\"uint256\"}],\"name\":\"getAgent\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_domainIndex\",\"type\":\"uint256\"}],\"name\":\"getDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_account\",\"type\":\"address\"}],\"name\":\"isActiveAgent\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_domain\",\"type\":\"uint32\"}],\"name\":\"isActiveDomain\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"localDomain\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"_systemRouter\",\"type\":\"address\"}],\"name\":\"setSystemRouter\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo\",\"name\":\"_info\",\"type\":\"tuple\"}],\"name\":\"slashAgent\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint32\",\"name\":\"_callOrigin\",\"type\":\"uint32\"},{\"internalType\":\"enumISystemRouter.SystemEntity\",\"name\":\"_caller\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_requestID\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"_removeExisting\",\"type\":\"bool\"},{\"components\":[{\"internalType\":\"uint32\",\"name\":\"domain\",\"type\":\"uint32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"bonded\",\"type\":\"bool\"}],\"internalType\":\"structSystemContract.AgentInfo[]\",\"name\":\"_infos\",\"type\":\"tuple[]\"}],\"name\":\"syncAgents\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"systemRouter\",\"outputs\":[{\"internalType\":\"contractISystemRouter\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"bf61e67e": "SYNAPSE_DOMAIN()",
		"64ecb518": "allAgents(uint32)",
		"6f225878": "allDomains()",
		"32254098": "amountAgents(uint32)",
		"61b0b357": "amountDomains()",
		"1d82873b": "getAgent(uint32,uint256)",
		"1a7a98e2": "getDomain(uint256)",
		"65e1e466": "isActiveAgent(address)",
		"0958117d": "isActiveAgent(uint32,address)",
		"4f5dbc0d": "isActiveDomain(uint32)",
		"8d3638f4": "localDomain()",
		"8da5cb5b": "owner()",
		"715018a6": "renounceOwnership()",
		"fbde22f7": "setSystemRouter(address)",
		"31f36451": "slashAgent(uint256,uint32,uint8,(uint32,address,bool))",
		"cc118b4d": "syncAgents(uint256,uint32,uint8,uint256,bool,(uint32,address,bool)[])",
		"529d1549": "systemRouter()",
		"f2fde38b": "transferOwnership(address)",
	},
}

// SystemRegistryABI is the input ABI used to generate the binding from.
// Deprecated: Use SystemRegistryMetaData.ABI instead.
var SystemRegistryABI = SystemRegistryMetaData.ABI

// Deprecated: Use SystemRegistryMetaData.Sigs instead.
// SystemRegistryFuncSigs maps the 4-byte function signature to its string representation.
var SystemRegistryFuncSigs = SystemRegistryMetaData.Sigs

// SystemRegistry is an auto generated Go binding around an Ethereum contract.
type SystemRegistry struct {
	SystemRegistryCaller     // Read-only binding to the contract
	SystemRegistryTransactor // Write-only binding to the contract
	SystemRegistryFilterer   // Log filterer for contract events
}

// SystemRegistryCaller is an auto generated read-only Go binding around an Ethereum contract.
type SystemRegistryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemRegistryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SystemRegistryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemRegistryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SystemRegistryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SystemRegistrySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SystemRegistrySession struct {
	Contract     *SystemRegistry   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SystemRegistryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SystemRegistryCallerSession struct {
	Contract *SystemRegistryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// SystemRegistryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SystemRegistryTransactorSession struct {
	Contract     *SystemRegistryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// SystemRegistryRaw is an auto generated low-level Go binding around an Ethereum contract.
type SystemRegistryRaw struct {
	Contract *SystemRegistry // Generic contract binding to access the raw methods on
}

// SystemRegistryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SystemRegistryCallerRaw struct {
	Contract *SystemRegistryCaller // Generic read-only contract binding to access the raw methods on
}

// SystemRegistryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SystemRegistryTransactorRaw struct {
	Contract *SystemRegistryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSystemRegistry creates a new instance of SystemRegistry, bound to a specific deployed contract.
func NewSystemRegistry(address common.Address, backend bind.ContractBackend) (*SystemRegistry, error) {
	contract, err := bindSystemRegistry(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SystemRegistry{SystemRegistryCaller: SystemRegistryCaller{contract: contract}, SystemRegistryTransactor: SystemRegistryTransactor{contract: contract}, SystemRegistryFilterer: SystemRegistryFilterer{contract: contract}}, nil
}

// NewSystemRegistryCaller creates a new read-only instance of SystemRegistry, bound to a specific deployed contract.
func NewSystemRegistryCaller(address common.Address, caller bind.ContractCaller) (*SystemRegistryCaller, error) {
	contract, err := bindSystemRegistry(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryCaller{contract: contract}, nil
}

// NewSystemRegistryTransactor creates a new write-only instance of SystemRegistry, bound to a specific deployed contract.
func NewSystemRegistryTransactor(address common.Address, transactor bind.ContractTransactor) (*SystemRegistryTransactor, error) {
	contract, err := bindSystemRegistry(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryTransactor{contract: contract}, nil
}

// NewSystemRegistryFilterer creates a new log filterer instance of SystemRegistry, bound to a specific deployed contract.
func NewSystemRegistryFilterer(address common.Address, filterer bind.ContractFilterer) (*SystemRegistryFilterer, error) {
	contract, err := bindSystemRegistry(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryFilterer{contract: contract}, nil
}

// bindSystemRegistry binds a generic wrapper to an already deployed contract.
func bindSystemRegistry(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(SystemRegistryABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SystemRegistry *SystemRegistryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SystemRegistry.Contract.SystemRegistryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SystemRegistry *SystemRegistryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SystemRegistryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SystemRegistry *SystemRegistryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SystemRegistryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SystemRegistry *SystemRegistryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SystemRegistry.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SystemRegistry *SystemRegistryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemRegistry.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SystemRegistry *SystemRegistryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SystemRegistry.Contract.contract.Transact(opts, method, params...)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_SystemRegistry *SystemRegistryCaller) SYNAPSEDOMAIN(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "SYNAPSE_DOMAIN")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_SystemRegistry *SystemRegistrySession) SYNAPSEDOMAIN() (uint32, error) {
	return _SystemRegistry.Contract.SYNAPSEDOMAIN(&_SystemRegistry.CallOpts)
}

// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
//
// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
func (_SystemRegistry *SystemRegistryCallerSession) SYNAPSEDOMAIN() (uint32, error) {
	return _SystemRegistry.Contract.SYNAPSEDOMAIN(&_SystemRegistry.CallOpts)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_SystemRegistry *SystemRegistryCaller) AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "allAgents", _domain)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_SystemRegistry *SystemRegistrySession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _SystemRegistry.Contract.AllAgents(&_SystemRegistry.CallOpts, _domain)
}

// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
//
// Solidity: function allAgents(uint32 _domain) view returns(address[])
func (_SystemRegistry *SystemRegistryCallerSession) AllAgents(_domain uint32) ([]common.Address, error) {
	return _SystemRegistry.Contract.AllAgents(&_SystemRegistry.CallOpts, _domain)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_SystemRegistry *SystemRegistryCaller) AllDomains(opts *bind.CallOpts) ([]uint32, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "allDomains")

	if err != nil {
		return *new([]uint32), err
	}

	out0 := *abi.ConvertType(out[0], new([]uint32)).(*[]uint32)

	return out0, err

}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_SystemRegistry *SystemRegistrySession) AllDomains() ([]uint32, error) {
	return _SystemRegistry.Contract.AllDomains(&_SystemRegistry.CallOpts)
}

// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
//
// Solidity: function allDomains() view returns(uint32[] domains_)
func (_SystemRegistry *SystemRegistryCallerSession) AllDomains() ([]uint32, error) {
	return _SystemRegistry.Contract.AllDomains(&_SystemRegistry.CallOpts)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_SystemRegistry *SystemRegistryCaller) AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "amountAgents", _domain)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_SystemRegistry *SystemRegistrySession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _SystemRegistry.Contract.AmountAgents(&_SystemRegistry.CallOpts, _domain)
}

// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
//
// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
func (_SystemRegistry *SystemRegistryCallerSession) AmountAgents(_domain uint32) (*big.Int, error) {
	return _SystemRegistry.Contract.AmountAgents(&_SystemRegistry.CallOpts, _domain)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_SystemRegistry *SystemRegistryCaller) AmountDomains(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "amountDomains")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_SystemRegistry *SystemRegistrySession) AmountDomains() (*big.Int, error) {
	return _SystemRegistry.Contract.AmountDomains(&_SystemRegistry.CallOpts)
}

// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
//
// Solidity: function amountDomains() view returns(uint256)
func (_SystemRegistry *SystemRegistryCallerSession) AmountDomains() (*big.Int, error) {
	return _SystemRegistry.Contract.AmountDomains(&_SystemRegistry.CallOpts)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_SystemRegistry *SystemRegistryCaller) GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "getAgent", _domain, _agentIndex)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_SystemRegistry *SystemRegistrySession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _SystemRegistry.Contract.GetAgent(&_SystemRegistry.CallOpts, _domain, _agentIndex)
}

// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
//
// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
func (_SystemRegistry *SystemRegistryCallerSession) GetAgent(_domain uint32, _agentIndex *big.Int) (common.Address, error) {
	return _SystemRegistry.Contract.GetAgent(&_SystemRegistry.CallOpts, _domain, _agentIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_SystemRegistry *SystemRegistryCaller) GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "getDomain", _domainIndex)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_SystemRegistry *SystemRegistrySession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _SystemRegistry.Contract.GetDomain(&_SystemRegistry.CallOpts, _domainIndex)
}

// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
//
// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
func (_SystemRegistry *SystemRegistryCallerSession) GetDomain(_domainIndex *big.Int) (uint32, error) {
	return _SystemRegistry.Contract.GetDomain(&_SystemRegistry.CallOpts, _domainIndex)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_SystemRegistry *SystemRegistryCaller) IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "isActiveAgent", _domain, _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_SystemRegistry *SystemRegistrySession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _SystemRegistry.Contract.IsActiveAgent(&_SystemRegistry.CallOpts, _domain, _account)
}

// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
//
// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
func (_SystemRegistry *SystemRegistryCallerSession) IsActiveAgent(_domain uint32, _account common.Address) (bool, error) {
	return _SystemRegistry.Contract.IsActiveAgent(&_SystemRegistry.CallOpts, _domain, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_SystemRegistry *SystemRegistryCaller) IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "isActiveAgent0", _account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_SystemRegistry *SystemRegistrySession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _SystemRegistry.Contract.IsActiveAgent0(&_SystemRegistry.CallOpts, _account)
}

// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
//
// Solidity: function isActiveAgent(address _account) view returns(bool)
func (_SystemRegistry *SystemRegistryCallerSession) IsActiveAgent0(_account common.Address) (bool, error) {
	return _SystemRegistry.Contract.IsActiveAgent0(&_SystemRegistry.CallOpts, _account)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_SystemRegistry *SystemRegistryCaller) IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "isActiveDomain", _domain)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_SystemRegistry *SystemRegistrySession) IsActiveDomain(_domain uint32) (bool, error) {
	return _SystemRegistry.Contract.IsActiveDomain(&_SystemRegistry.CallOpts, _domain)
}

// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
//
// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
func (_SystemRegistry *SystemRegistryCallerSession) IsActiveDomain(_domain uint32) (bool, error) {
	return _SystemRegistry.Contract.IsActiveDomain(&_SystemRegistry.CallOpts, _domain)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_SystemRegistry *SystemRegistryCaller) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "localDomain")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_SystemRegistry *SystemRegistrySession) LocalDomain() (uint32, error) {
	return _SystemRegistry.Contract.LocalDomain(&_SystemRegistry.CallOpts)
}

// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
//
// Solidity: function localDomain() view returns(uint32)
func (_SystemRegistry *SystemRegistryCallerSession) LocalDomain() (uint32, error) {
	return _SystemRegistry.Contract.LocalDomain(&_SystemRegistry.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SystemRegistry *SystemRegistryCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SystemRegistry *SystemRegistrySession) Owner() (common.Address, error) {
	return _SystemRegistry.Contract.Owner(&_SystemRegistry.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_SystemRegistry *SystemRegistryCallerSession) Owner() (common.Address, error) {
	return _SystemRegistry.Contract.Owner(&_SystemRegistry.CallOpts)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_SystemRegistry *SystemRegistryCaller) SystemRouter(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _SystemRegistry.contract.Call(opts, &out, "systemRouter")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_SystemRegistry *SystemRegistrySession) SystemRouter() (common.Address, error) {
	return _SystemRegistry.Contract.SystemRouter(&_SystemRegistry.CallOpts)
}

// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
//
// Solidity: function systemRouter() view returns(address)
func (_SystemRegistry *SystemRegistryCallerSession) SystemRouter() (common.Address, error) {
	return _SystemRegistry.Contract.SystemRouter(&_SystemRegistry.CallOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SystemRegistry *SystemRegistryTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SystemRegistry.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SystemRegistry *SystemRegistrySession) RenounceOwnership() (*types.Transaction, error) {
	return _SystemRegistry.Contract.RenounceOwnership(&_SystemRegistry.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_SystemRegistry *SystemRegistryTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _SystemRegistry.Contract.RenounceOwnership(&_SystemRegistry.TransactOpts)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_SystemRegistry *SystemRegistryTransactor) SetSystemRouter(opts *bind.TransactOpts, _systemRouter common.Address) (*types.Transaction, error) {
	return _SystemRegistry.contract.Transact(opts, "setSystemRouter", _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_SystemRegistry *SystemRegistrySession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SetSystemRouter(&_SystemRegistry.TransactOpts, _systemRouter)
}

// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
//
// Solidity: function setSystemRouter(address _systemRouter) returns()
func (_SystemRegistry *SystemRegistryTransactorSession) SetSystemRouter(_systemRouter common.Address) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SetSystemRouter(&_SystemRegistry.TransactOpts, _systemRouter)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_SystemRegistry *SystemRegistryTransactor) SlashAgent(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemRegistry.contract.Transact(opts, "slashAgent", arg0, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_SystemRegistry *SystemRegistrySession) SlashAgent(arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SlashAgent(&_SystemRegistry.TransactOpts, arg0, _callOrigin, _caller, _info)
}

// SlashAgent is a paid mutator transaction binding the contract method 0x31f36451.
//
// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint32,address,bool) _info) returns()
func (_SystemRegistry *SystemRegistryTransactorSession) SlashAgent(arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SlashAgent(&_SystemRegistry.TransactOpts, arg0, _callOrigin, _caller, _info)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_SystemRegistry *SystemRegistryTransactor) SyncAgents(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemRegistry.contract.Transact(opts, "syncAgents", arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_SystemRegistry *SystemRegistrySession) SyncAgents(arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SyncAgents(&_SystemRegistry.TransactOpts, arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// SyncAgents is a paid mutator transaction binding the contract method 0xcc118b4d.
//
// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint32,address,bool)[] _infos) returns()
func (_SystemRegistry *SystemRegistryTransactorSession) SyncAgents(arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error) {
	return _SystemRegistry.Contract.SyncAgents(&_SystemRegistry.TransactOpts, arg0, _callOrigin, _caller, _requestID, _removeExisting, _infos)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SystemRegistry *SystemRegistryTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _SystemRegistry.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SystemRegistry *SystemRegistrySession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SystemRegistry.Contract.TransferOwnership(&_SystemRegistry.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_SystemRegistry *SystemRegistryTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _SystemRegistry.Contract.TransferOwnership(&_SystemRegistry.TransactOpts, newOwner)
}

// SystemRegistryAgentAddedIterator is returned from FilterAgentAdded and is used to iterate over the raw logs and unpacked data for AgentAdded events raised by the SystemRegistry contract.
type SystemRegistryAgentAddedIterator struct {
	Event *SystemRegistryAgentAdded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemRegistryAgentAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemRegistryAgentAdded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemRegistryAgentAdded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemRegistryAgentAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemRegistryAgentAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemRegistryAgentAdded represents a AgentAdded event raised by the SystemRegistry contract.
type SystemRegistryAgentAdded struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentAdded is a free log retrieval operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_SystemRegistry *SystemRegistryFilterer) FilterAgentAdded(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*SystemRegistryAgentAddedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SystemRegistry.contract.FilterLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryAgentAddedIterator{contract: _SystemRegistry.contract, event: "AgentAdded", logs: logs, sub: sub}, nil
}

// WatchAgentAdded is a free log subscription operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_SystemRegistry *SystemRegistryFilterer) WatchAgentAdded(opts *bind.WatchOpts, sink chan<- *SystemRegistryAgentAdded, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SystemRegistry.contract.WatchLogs(opts, "AgentAdded", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemRegistryAgentAdded)
				if err := _SystemRegistry.contract.UnpackLog(event, "AgentAdded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentAdded is a log parse operation binding the contract event 0xf317002dd4275e311428a6702ca0c0dd258ccd819733937b3c325f9fa7d2dd6d.
//
// Solidity: event AgentAdded(uint32 indexed domain, address indexed account)
func (_SystemRegistry *SystemRegistryFilterer) ParseAgentAdded(log types.Log) (*SystemRegistryAgentAdded, error) {
	event := new(SystemRegistryAgentAdded)
	if err := _SystemRegistry.contract.UnpackLog(event, "AgentAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemRegistryAgentRemovedIterator is returned from FilterAgentRemoved and is used to iterate over the raw logs and unpacked data for AgentRemoved events raised by the SystemRegistry contract.
type SystemRegistryAgentRemovedIterator struct {
	Event *SystemRegistryAgentRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemRegistryAgentRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemRegistryAgentRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemRegistryAgentRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemRegistryAgentRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemRegistryAgentRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemRegistryAgentRemoved represents a AgentRemoved event raised by the SystemRegistry contract.
type SystemRegistryAgentRemoved struct {
	Domain  uint32
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAgentRemoved is a free log retrieval operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_SystemRegistry *SystemRegistryFilterer) FilterAgentRemoved(opts *bind.FilterOpts, domain []uint32, account []common.Address) (*SystemRegistryAgentRemovedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SystemRegistry.contract.FilterLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryAgentRemovedIterator{contract: _SystemRegistry.contract, event: "AgentRemoved", logs: logs, sub: sub}, nil
}

// WatchAgentRemoved is a free log subscription operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_SystemRegistry *SystemRegistryFilterer) WatchAgentRemoved(opts *bind.WatchOpts, sink chan<- *SystemRegistryAgentRemoved, domain []uint32, account []common.Address) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SystemRegistry.contract.WatchLogs(opts, "AgentRemoved", domainRule, accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemRegistryAgentRemoved)
				if err := _SystemRegistry.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentRemoved is a log parse operation binding the contract event 0x36c9058f377a833904163847910be07fdfc0d1f90d885d7f2749713d9913852e.
//
// Solidity: event AgentRemoved(uint32 indexed domain, address indexed account)
func (_SystemRegistry *SystemRegistryFilterer) ParseAgentRemoved(log types.Log) (*SystemRegistryAgentRemoved, error) {
	event := new(SystemRegistryAgentRemoved)
	if err := _SystemRegistry.contract.UnpackLog(event, "AgentRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemRegistryDomainActivatedIterator is returned from FilterDomainActivated and is used to iterate over the raw logs and unpacked data for DomainActivated events raised by the SystemRegistry contract.
type SystemRegistryDomainActivatedIterator struct {
	Event *SystemRegistryDomainActivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemRegistryDomainActivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemRegistryDomainActivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemRegistryDomainActivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemRegistryDomainActivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemRegistryDomainActivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemRegistryDomainActivated represents a DomainActivated event raised by the SystemRegistry contract.
type SystemRegistryDomainActivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainActivated is a free log retrieval operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_SystemRegistry *SystemRegistryFilterer) FilterDomainActivated(opts *bind.FilterOpts, domain []uint32) (*SystemRegistryDomainActivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _SystemRegistry.contract.FilterLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryDomainActivatedIterator{contract: _SystemRegistry.contract, event: "DomainActivated", logs: logs, sub: sub}, nil
}

// WatchDomainActivated is a free log subscription operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_SystemRegistry *SystemRegistryFilterer) WatchDomainActivated(opts *bind.WatchOpts, sink chan<- *SystemRegistryDomainActivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _SystemRegistry.contract.WatchLogs(opts, "DomainActivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemRegistryDomainActivated)
				if err := _SystemRegistry.contract.UnpackLog(event, "DomainActivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainActivated is a log parse operation binding the contract event 0x05b9ad808d73157589dfae619d8942273dafcd3ec0a49b8f33a573410c0f1222.
//
// Solidity: event DomainActivated(uint32 indexed domain)
func (_SystemRegistry *SystemRegistryFilterer) ParseDomainActivated(log types.Log) (*SystemRegistryDomainActivated, error) {
	event := new(SystemRegistryDomainActivated)
	if err := _SystemRegistry.contract.UnpackLog(event, "DomainActivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemRegistryDomainDeactivatedIterator is returned from FilterDomainDeactivated and is used to iterate over the raw logs and unpacked data for DomainDeactivated events raised by the SystemRegistry contract.
type SystemRegistryDomainDeactivatedIterator struct {
	Event *SystemRegistryDomainDeactivated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemRegistryDomainDeactivatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemRegistryDomainDeactivated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemRegistryDomainDeactivated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemRegistryDomainDeactivatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemRegistryDomainDeactivatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemRegistryDomainDeactivated represents a DomainDeactivated event raised by the SystemRegistry contract.
type SystemRegistryDomainDeactivated struct {
	Domain uint32
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterDomainDeactivated is a free log retrieval operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_SystemRegistry *SystemRegistryFilterer) FilterDomainDeactivated(opts *bind.FilterOpts, domain []uint32) (*SystemRegistryDomainDeactivatedIterator, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _SystemRegistry.contract.FilterLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryDomainDeactivatedIterator{contract: _SystemRegistry.contract, event: "DomainDeactivated", logs: logs, sub: sub}, nil
}

// WatchDomainDeactivated is a free log subscription operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_SystemRegistry *SystemRegistryFilterer) WatchDomainDeactivated(opts *bind.WatchOpts, sink chan<- *SystemRegistryDomainDeactivated, domain []uint32) (event.Subscription, error) {

	var domainRule []interface{}
	for _, domainItem := range domain {
		domainRule = append(domainRule, domainItem)
	}

	logs, sub, err := _SystemRegistry.contract.WatchLogs(opts, "DomainDeactivated", domainRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemRegistryDomainDeactivated)
				if err := _SystemRegistry.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDomainDeactivated is a log parse operation binding the contract event 0xa7654f2ff76a0d100f23fd02cae38d87b3fdf3c5d36b7f4df3bd5cc285816a19.
//
// Solidity: event DomainDeactivated(uint32 indexed domain)
func (_SystemRegistry *SystemRegistryFilterer) ParseDomainDeactivated(log types.Log) (*SystemRegistryDomainDeactivated, error) {
	event := new(SystemRegistryDomainDeactivated)
	if err := _SystemRegistry.contract.UnpackLog(event, "DomainDeactivated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemRegistryInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the SystemRegistry contract.
type SystemRegistryInitializedIterator struct {
	Event *SystemRegistryInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemRegistryInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemRegistryInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemRegistryInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemRegistryInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemRegistryInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemRegistryInitialized represents a Initialized event raised by the SystemRegistry contract.
type SystemRegistryInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_SystemRegistry *SystemRegistryFilterer) FilterInitialized(opts *bind.FilterOpts) (*SystemRegistryInitializedIterator, error) {

	logs, sub, err := _SystemRegistry.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &SystemRegistryInitializedIterator{contract: _SystemRegistry.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_SystemRegistry *SystemRegistryFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *SystemRegistryInitialized) (event.Subscription, error) {

	logs, sub, err := _SystemRegistry.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemRegistryInitialized)
				if err := _SystemRegistry.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_SystemRegistry *SystemRegistryFilterer) ParseInitialized(log types.Log) (*SystemRegistryInitialized, error) {
	event := new(SystemRegistryInitialized)
	if err := _SystemRegistry.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SystemRegistryOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the SystemRegistry contract.
type SystemRegistryOwnershipTransferredIterator struct {
	Event *SystemRegistryOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SystemRegistryOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SystemRegistryOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SystemRegistryOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SystemRegistryOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SystemRegistryOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SystemRegistryOwnershipTransferred represents a OwnershipTransferred event raised by the SystemRegistry contract.
type SystemRegistryOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SystemRegistry *SystemRegistryFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*SystemRegistryOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SystemRegistry.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &SystemRegistryOwnershipTransferredIterator{contract: _SystemRegistry.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SystemRegistry *SystemRegistryFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *SystemRegistryOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _SystemRegistry.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SystemRegistryOwnershipTransferred)
				if err := _SystemRegistry.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_SystemRegistry *SystemRegistryFilterer) ParseOwnershipTransferred(log types.Log) (*SystemRegistryOwnershipTransferred, error) {
	event := new(SystemRegistryOwnershipTransferred)
	if err := _SystemRegistry.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TipsMetaData contains all meta data concerning the Tips contract.
var TipsMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea26469706673582212201c8730852e562285045ed2d65d2e8dce9f5404625520ee558d64a63356c186ca64736f6c63430008110033",
}

// TipsABI is the input ABI used to generate the binding from.
// Deprecated: Use TipsMetaData.ABI instead.
var TipsABI = TipsMetaData.ABI

// TipsBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use TipsMetaData.Bin instead.
var TipsBin = TipsMetaData.Bin

// DeployTips deploys a new Ethereum contract, binding an instance of Tips to it.
func DeployTips(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Tips, error) {
	parsed, err := TipsMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(TipsBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Tips{TipsCaller: TipsCaller{contract: contract}, TipsTransactor: TipsTransactor{contract: contract}, TipsFilterer: TipsFilterer{contract: contract}}, nil
}

// Tips is an auto generated Go binding around an Ethereum contract.
type Tips struct {
	TipsCaller     // Read-only binding to the contract
	TipsTransactor // Write-only binding to the contract
	TipsFilterer   // Log filterer for contract events
}

// TipsCaller is an auto generated read-only Go binding around an Ethereum contract.
type TipsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TipsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TipsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TipsFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TipsFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TipsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TipsSession struct {
	Contract     *Tips             // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// TipsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TipsCallerSession struct {
	Contract *TipsCaller   // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// TipsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TipsTransactorSession struct {
	Contract     *TipsTransactor   // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// TipsRaw is an auto generated low-level Go binding around an Ethereum contract.
type TipsRaw struct {
	Contract *Tips // Generic contract binding to access the raw methods on
}

// TipsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TipsCallerRaw struct {
	Contract *TipsCaller // Generic read-only contract binding to access the raw methods on
}

// TipsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TipsTransactorRaw struct {
	Contract *TipsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTips creates a new instance of Tips, bound to a specific deployed contract.
func NewTips(address common.Address, backend bind.ContractBackend) (*Tips, error) {
	contract, err := bindTips(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Tips{TipsCaller: TipsCaller{contract: contract}, TipsTransactor: TipsTransactor{contract: contract}, TipsFilterer: TipsFilterer{contract: contract}}, nil
}

// NewTipsCaller creates a new read-only instance of Tips, bound to a specific deployed contract.
func NewTipsCaller(address common.Address, caller bind.ContractCaller) (*TipsCaller, error) {
	contract, err := bindTips(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TipsCaller{contract: contract}, nil
}

// NewTipsTransactor creates a new write-only instance of Tips, bound to a specific deployed contract.
func NewTipsTransactor(address common.Address, transactor bind.ContractTransactor) (*TipsTransactor, error) {
	contract, err := bindTips(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TipsTransactor{contract: contract}, nil
}

// NewTipsFilterer creates a new log filterer instance of Tips, bound to a specific deployed contract.
func NewTipsFilterer(address common.Address, filterer bind.ContractFilterer) (*TipsFilterer, error) {
	contract, err := bindTips(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TipsFilterer{contract: contract}, nil
}

// bindTips binds a generic wrapper to an already deployed contract.
func bindTips(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(TipsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Tips *TipsRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Tips.Contract.TipsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Tips *TipsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Tips.Contract.TipsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Tips *TipsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Tips.Contract.TipsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Tips *TipsCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Tips.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Tips *TipsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Tips.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Tips *TipsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Tips.Contract.contract.Transact(opts, method, params...)
}

// TypeCastsMetaData contains all meta data concerning the TypeCasts contract.
var TypeCastsMetaData = &bind.MetaData{
	ABI: "[]",
	Bin: "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122027b283d2ef2415e6c001fdf0d35bf6549507e80983475c806aeee80f84461a3264736f6c63430008110033",
}

// TypeCastsABI is the input ABI used to generate the binding from.
// Deprecated: Use TypeCastsMetaData.ABI instead.
var TypeCastsABI = TypeCastsMetaData.ABI

// TypeCastsBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use TypeCastsMetaData.Bin instead.
var TypeCastsBin = TypeCastsMetaData.Bin

// DeployTypeCasts deploys a new Ethereum contract, binding an instance of TypeCasts to it.
func DeployTypeCasts(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *TypeCasts, error) {
	parsed, err := TypeCastsMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(TypeCastsBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &TypeCasts{TypeCastsCaller: TypeCastsCaller{contract: contract}, TypeCastsTransactor: TypeCastsTransactor{contract: contract}, TypeCastsFilterer: TypeCastsFilterer{contract: contract}}, nil
}

// TypeCasts is an auto generated Go binding around an Ethereum contract.
type TypeCasts struct {
	TypeCastsCaller     // Read-only binding to the contract
	TypeCastsTransactor // Write-only binding to the contract
	TypeCastsFilterer   // Log filterer for contract events
}

// TypeCastsCaller is an auto generated read-only Go binding around an Ethereum contract.
type TypeCastsCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TypeCastsTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TypeCastsTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TypeCastsFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TypeCastsFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TypeCastsSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TypeCastsSession struct {
	Contract     *TypeCasts        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// TypeCastsCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TypeCastsCallerSession struct {
	Contract *TypeCastsCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// TypeCastsTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TypeCastsTransactorSession struct {
	Contract     *TypeCastsTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// TypeCastsRaw is an auto generated low-level Go binding around an Ethereum contract.
type TypeCastsRaw struct {
	Contract *TypeCasts // Generic contract binding to access the raw methods on
}

// TypeCastsCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TypeCastsCallerRaw struct {
	Contract *TypeCastsCaller // Generic read-only contract binding to access the raw methods on
}

// TypeCastsTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TypeCastsTransactorRaw struct {
	Contract *TypeCastsTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTypeCasts creates a new instance of TypeCasts, bound to a specific deployed contract.
func NewTypeCasts(address common.Address, backend bind.ContractBackend) (*TypeCasts, error) {
	contract, err := bindTypeCasts(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &TypeCasts{TypeCastsCaller: TypeCastsCaller{contract: contract}, TypeCastsTransactor: TypeCastsTransactor{contract: contract}, TypeCastsFilterer: TypeCastsFilterer{contract: contract}}, nil
}

// NewTypeCastsCaller creates a new read-only instance of TypeCasts, bound to a specific deployed contract.
func NewTypeCastsCaller(address common.Address, caller bind.ContractCaller) (*TypeCastsCaller, error) {
	contract, err := bindTypeCasts(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TypeCastsCaller{contract: contract}, nil
}

// NewTypeCastsTransactor creates a new write-only instance of TypeCasts, bound to a specific deployed contract.
func NewTypeCastsTransactor(address common.Address, transactor bind.ContractTransactor) (*TypeCastsTransactor, error) {
	contract, err := bindTypeCasts(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TypeCastsTransactor{contract: contract}, nil
}

// NewTypeCastsFilterer creates a new log filterer instance of TypeCasts, bound to a specific deployed contract.
func NewTypeCastsFilterer(address common.Address, filterer bind.ContractFilterer) (*TypeCastsFilterer, error) {
	contract, err := bindTypeCasts(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TypeCastsFilterer{contract: contract}, nil
}

// bindTypeCasts binds a generic wrapper to an already deployed contract.
func bindTypeCasts(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(TypeCastsABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TypeCasts *TypeCastsRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TypeCasts.Contract.TypeCastsCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TypeCasts *TypeCastsRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TypeCasts.Contract.TypeCastsTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TypeCasts *TypeCastsRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TypeCasts.Contract.TypeCastsTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TypeCasts *TypeCastsCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TypeCasts.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TypeCasts *TypeCastsTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TypeCasts.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TypeCasts *TypeCastsTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TypeCasts.Contract.contract.Transact(opts, method, params...)
}

// TypedMemViewMetaData contains all meta data concerning the TypedMemView contract.
var TypedMemViewMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"BITS_EMPTY\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"BITS_LEN\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"BITS_LOC\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"BITS_TYPE\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"LOW_96_BITS_MASK\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"NULL\",\"outputs\":[{\"internalType\":\"bytes29\",\"name\":\"\",\"type\":\"bytes29\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"SHIFT_LEN\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"SHIFT_LOC\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"SHIFT_TYPE\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"97b8ad4a": "BITS_EMPTY()",
		"eb740628": "BITS_LEN()",
		"fb734584": "BITS_LOC()",
		"10153fce": "BITS_TYPE()",
		"b602d173": "LOW_96_BITS_MASK()",
		"f26be3fc": "NULL()",
		"1136e7ea": "SHIFT_LEN()",
		"1bfe17ce": "SHIFT_LOC()",
		"13090c5a": "SHIFT_TYPE()",
	},
	Bin: "0x6101f061003a600b82828239805160001a60731461002d57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600436106100ad5760003560e01c806397b8ad4a11610080578063eb74062811610065578063eb740628146100f8578063f26be3fc14610100578063fb734584146100f857600080fd5b806397b8ad4a146100cd578063b602d173146100e557600080fd5b806310153fce146100b25780631136e7ea146100cd57806313090c5a146100d55780631bfe17ce146100dd575b600080fd5b6100ba602881565b6040519081526020015b60405180910390f35b6100ba601881565b6100ba610158565b6100ba610172565b6100ba6bffffffffffffffffffffffff81565b6100ba606081565b6101277fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000081565b6040517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000090911681526020016100c4565b606061016581601861017a565b61016f919061017a565b81565b61016f606060185b808201808211156101b4577f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b9291505056fea2646970667358221220275ac554c122a3196821f20b2ebf35a9549fc106e638e388c550e59ecd4dbeaa64736f6c63430008110033",
}

// TypedMemViewABI is the input ABI used to generate the binding from.
// Deprecated: Use TypedMemViewMetaData.ABI instead.
var TypedMemViewABI = TypedMemViewMetaData.ABI

// Deprecated: Use TypedMemViewMetaData.Sigs instead.
// TypedMemViewFuncSigs maps the 4-byte function signature to its string representation.
var TypedMemViewFuncSigs = TypedMemViewMetaData.Sigs

// TypedMemViewBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use TypedMemViewMetaData.Bin instead.
var TypedMemViewBin = TypedMemViewMetaData.Bin

// DeployTypedMemView deploys a new Ethereum contract, binding an instance of TypedMemView to it.
func DeployTypedMemView(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *TypedMemView, error) {
	parsed, err := TypedMemViewMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(TypedMemViewBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &TypedMemView{TypedMemViewCaller: TypedMemViewCaller{contract: contract}, TypedMemViewTransactor: TypedMemViewTransactor{contract: contract}, TypedMemViewFilterer: TypedMemViewFilterer{contract: contract}}, nil
}

// TypedMemView is an auto generated Go binding around an Ethereum contract.
type TypedMemView struct {
	TypedMemViewCaller     // Read-only binding to the contract
	TypedMemViewTransactor // Write-only binding to the contract
	TypedMemViewFilterer   // Log filterer for contract events
}

// TypedMemViewCaller is an auto generated read-only Go binding around an Ethereum contract.
type TypedMemViewCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TypedMemViewTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TypedMemViewTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TypedMemViewFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TypedMemViewFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TypedMemViewSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TypedMemViewSession struct {
	Contract     *TypedMemView     // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// TypedMemViewCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TypedMemViewCallerSession struct {
	Contract *TypedMemViewCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts       // Call options to use throughout this session
}

// TypedMemViewTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TypedMemViewTransactorSession struct {
	Contract     *TypedMemViewTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// TypedMemViewRaw is an auto generated low-level Go binding around an Ethereum contract.
type TypedMemViewRaw struct {
	Contract *TypedMemView // Generic contract binding to access the raw methods on
}

// TypedMemViewCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TypedMemViewCallerRaw struct {
	Contract *TypedMemViewCaller // Generic read-only contract binding to access the raw methods on
}

// TypedMemViewTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TypedMemViewTransactorRaw struct {
	Contract *TypedMemViewTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTypedMemView creates a new instance of TypedMemView, bound to a specific deployed contract.
func NewTypedMemView(address common.Address, backend bind.ContractBackend) (*TypedMemView, error) {
	contract, err := bindTypedMemView(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &TypedMemView{TypedMemViewCaller: TypedMemViewCaller{contract: contract}, TypedMemViewTransactor: TypedMemViewTransactor{contract: contract}, TypedMemViewFilterer: TypedMemViewFilterer{contract: contract}}, nil
}

// NewTypedMemViewCaller creates a new read-only instance of TypedMemView, bound to a specific deployed contract.
func NewTypedMemViewCaller(address common.Address, caller bind.ContractCaller) (*TypedMemViewCaller, error) {
	contract, err := bindTypedMemView(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TypedMemViewCaller{contract: contract}, nil
}

// NewTypedMemViewTransactor creates a new write-only instance of TypedMemView, bound to a specific deployed contract.
func NewTypedMemViewTransactor(address common.Address, transactor bind.ContractTransactor) (*TypedMemViewTransactor, error) {
	contract, err := bindTypedMemView(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TypedMemViewTransactor{contract: contract}, nil
}

// NewTypedMemViewFilterer creates a new log filterer instance of TypedMemView, bound to a specific deployed contract.
func NewTypedMemViewFilterer(address common.Address, filterer bind.ContractFilterer) (*TypedMemViewFilterer, error) {
	contract, err := bindTypedMemView(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TypedMemViewFilterer{contract: contract}, nil
}

// bindTypedMemView binds a generic wrapper to an already deployed contract.
func bindTypedMemView(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(TypedMemViewABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TypedMemView *TypedMemViewRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TypedMemView.Contract.TypedMemViewCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TypedMemView *TypedMemViewRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TypedMemView.Contract.TypedMemViewTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TypedMemView *TypedMemViewRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TypedMemView.Contract.TypedMemViewTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TypedMemView *TypedMemViewCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TypedMemView.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TypedMemView *TypedMemViewTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TypedMemView.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TypedMemView *TypedMemViewTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TypedMemView.Contract.contract.Transact(opts, method, params...)
}

// BITSEMPTY is a free data retrieval call binding the contract method 0x97b8ad4a.
//
// Solidity: function BITS_EMPTY() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) BITSEMPTY(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "BITS_EMPTY")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BITSEMPTY is a free data retrieval call binding the contract method 0x97b8ad4a.
//
// Solidity: function BITS_EMPTY() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) BITSEMPTY() (*big.Int, error) {
	return _TypedMemView.Contract.BITSEMPTY(&_TypedMemView.CallOpts)
}

// BITSEMPTY is a free data retrieval call binding the contract method 0x97b8ad4a.
//
// Solidity: function BITS_EMPTY() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) BITSEMPTY() (*big.Int, error) {
	return _TypedMemView.Contract.BITSEMPTY(&_TypedMemView.CallOpts)
}

// BITSLEN is a free data retrieval call binding the contract method 0xeb740628.
//
// Solidity: function BITS_LEN() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) BITSLEN(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "BITS_LEN")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BITSLEN is a free data retrieval call binding the contract method 0xeb740628.
//
// Solidity: function BITS_LEN() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) BITSLEN() (*big.Int, error) {
	return _TypedMemView.Contract.BITSLEN(&_TypedMemView.CallOpts)
}

// BITSLEN is a free data retrieval call binding the contract method 0xeb740628.
//
// Solidity: function BITS_LEN() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) BITSLEN() (*big.Int, error) {
	return _TypedMemView.Contract.BITSLEN(&_TypedMemView.CallOpts)
}

// BITSLOC is a free data retrieval call binding the contract method 0xfb734584.
//
// Solidity: function BITS_LOC() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) BITSLOC(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "BITS_LOC")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BITSLOC is a free data retrieval call binding the contract method 0xfb734584.
//
// Solidity: function BITS_LOC() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) BITSLOC() (*big.Int, error) {
	return _TypedMemView.Contract.BITSLOC(&_TypedMemView.CallOpts)
}

// BITSLOC is a free data retrieval call binding the contract method 0xfb734584.
//
// Solidity: function BITS_LOC() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) BITSLOC() (*big.Int, error) {
	return _TypedMemView.Contract.BITSLOC(&_TypedMemView.CallOpts)
}

// BITSTYPE is a free data retrieval call binding the contract method 0x10153fce.
//
// Solidity: function BITS_TYPE() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) BITSTYPE(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "BITS_TYPE")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BITSTYPE is a free data retrieval call binding the contract method 0x10153fce.
//
// Solidity: function BITS_TYPE() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) BITSTYPE() (*big.Int, error) {
	return _TypedMemView.Contract.BITSTYPE(&_TypedMemView.CallOpts)
}

// BITSTYPE is a free data retrieval call binding the contract method 0x10153fce.
//
// Solidity: function BITS_TYPE() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) BITSTYPE() (*big.Int, error) {
	return _TypedMemView.Contract.BITSTYPE(&_TypedMemView.CallOpts)
}

// LOW96BITSMASK is a free data retrieval call binding the contract method 0xb602d173.
//
// Solidity: function LOW_96_BITS_MASK() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) LOW96BITSMASK(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "LOW_96_BITS_MASK")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// LOW96BITSMASK is a free data retrieval call binding the contract method 0xb602d173.
//
// Solidity: function LOW_96_BITS_MASK() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) LOW96BITSMASK() (*big.Int, error) {
	return _TypedMemView.Contract.LOW96BITSMASK(&_TypedMemView.CallOpts)
}

// LOW96BITSMASK is a free data retrieval call binding the contract method 0xb602d173.
//
// Solidity: function LOW_96_BITS_MASK() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) LOW96BITSMASK() (*big.Int, error) {
	return _TypedMemView.Contract.LOW96BITSMASK(&_TypedMemView.CallOpts)
}

// NULL is a free data retrieval call binding the contract method 0xf26be3fc.
//
// Solidity: function NULL() view returns(bytes29)
func (_TypedMemView *TypedMemViewCaller) NULL(opts *bind.CallOpts) ([29]byte, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "NULL")

	if err != nil {
		return *new([29]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([29]byte)).(*[29]byte)

	return out0, err

}

// NULL is a free data retrieval call binding the contract method 0xf26be3fc.
//
// Solidity: function NULL() view returns(bytes29)
func (_TypedMemView *TypedMemViewSession) NULL() ([29]byte, error) {
	return _TypedMemView.Contract.NULL(&_TypedMemView.CallOpts)
}

// NULL is a free data retrieval call binding the contract method 0xf26be3fc.
//
// Solidity: function NULL() view returns(bytes29)
func (_TypedMemView *TypedMemViewCallerSession) NULL() ([29]byte, error) {
	return _TypedMemView.Contract.NULL(&_TypedMemView.CallOpts)
}

// SHIFTLEN is a free data retrieval call binding the contract method 0x1136e7ea.
//
// Solidity: function SHIFT_LEN() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) SHIFTLEN(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "SHIFT_LEN")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SHIFTLEN is a free data retrieval call binding the contract method 0x1136e7ea.
//
// Solidity: function SHIFT_LEN() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) SHIFTLEN() (*big.Int, error) {
	return _TypedMemView.Contract.SHIFTLEN(&_TypedMemView.CallOpts)
}

// SHIFTLEN is a free data retrieval call binding the contract method 0x1136e7ea.
//
// Solidity: function SHIFT_LEN() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) SHIFTLEN() (*big.Int, error) {
	return _TypedMemView.Contract.SHIFTLEN(&_TypedMemView.CallOpts)
}

// SHIFTLOC is a free data retrieval call binding the contract method 0x1bfe17ce.
//
// Solidity: function SHIFT_LOC() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) SHIFTLOC(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "SHIFT_LOC")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SHIFTLOC is a free data retrieval call binding the contract method 0x1bfe17ce.
//
// Solidity: function SHIFT_LOC() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) SHIFTLOC() (*big.Int, error) {
	return _TypedMemView.Contract.SHIFTLOC(&_TypedMemView.CallOpts)
}

// SHIFTLOC is a free data retrieval call binding the contract method 0x1bfe17ce.
//
// Solidity: function SHIFT_LOC() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) SHIFTLOC() (*big.Int, error) {
	return _TypedMemView.Contract.SHIFTLOC(&_TypedMemView.CallOpts)
}

// SHIFTTYPE is a free data retrieval call binding the contract method 0x13090c5a.
//
// Solidity: function SHIFT_TYPE() view returns(uint256)
func (_TypedMemView *TypedMemViewCaller) SHIFTTYPE(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TypedMemView.contract.Call(opts, &out, "SHIFT_TYPE")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SHIFTTYPE is a free data retrieval call binding the contract method 0x13090c5a.
//
// Solidity: function SHIFT_TYPE() view returns(uint256)
func (_TypedMemView *TypedMemViewSession) SHIFTTYPE() (*big.Int, error) {
	return _TypedMemView.Contract.SHIFTTYPE(&_TypedMemView.CallOpts)
}

// SHIFTTYPE is a free data retrieval call binding the contract method 0x13090c5a.
//
// Solidity: function SHIFT_TYPE() view returns(uint256)
func (_TypedMemView *TypedMemViewCallerSession) SHIFTTYPE() (*big.Int, error) {
	return _TypedMemView.Contract.SHIFTTYPE(&_TypedMemView.CallOpts)
}

// Version001MetaData contains all meta data concerning the Version001 contract.
var Version001MetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"versionString\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"54fd4d50": "version()",
	},
}

// Version001ABI is the input ABI used to generate the binding from.
// Deprecated: Use Version001MetaData.ABI instead.
var Version001ABI = Version001MetaData.ABI

// Deprecated: Use Version001MetaData.Sigs instead.
// Version001FuncSigs maps the 4-byte function signature to its string representation.
var Version001FuncSigs = Version001MetaData.Sigs

// Version001 is an auto generated Go binding around an Ethereum contract.
type Version001 struct {
	Version001Caller     // Read-only binding to the contract
	Version001Transactor // Write-only binding to the contract
	Version001Filterer   // Log filterer for contract events
}

// Version001Caller is an auto generated read-only Go binding around an Ethereum contract.
type Version001Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Version001Transactor is an auto generated write-only Go binding around an Ethereum contract.
type Version001Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Version001Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type Version001Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Version001Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type Version001Session struct {
	Contract     *Version001       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// Version001CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type Version001CallerSession struct {
	Contract *Version001Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// Version001TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type Version001TransactorSession struct {
	Contract     *Version001Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// Version001Raw is an auto generated low-level Go binding around an Ethereum contract.
type Version001Raw struct {
	Contract *Version001 // Generic contract binding to access the raw methods on
}

// Version001CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type Version001CallerRaw struct {
	Contract *Version001Caller // Generic read-only contract binding to access the raw methods on
}

// Version001TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type Version001TransactorRaw struct {
	Contract *Version001Transactor // Generic write-only contract binding to access the raw methods on
}

// NewVersion001 creates a new instance of Version001, bound to a specific deployed contract.
func NewVersion001(address common.Address, backend bind.ContractBackend) (*Version001, error) {
	contract, err := bindVersion001(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Version001{Version001Caller: Version001Caller{contract: contract}, Version001Transactor: Version001Transactor{contract: contract}, Version001Filterer: Version001Filterer{contract: contract}}, nil
}

// NewVersion001Caller creates a new read-only instance of Version001, bound to a specific deployed contract.
func NewVersion001Caller(address common.Address, caller bind.ContractCaller) (*Version001Caller, error) {
	contract, err := bindVersion001(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &Version001Caller{contract: contract}, nil
}

// NewVersion001Transactor creates a new write-only instance of Version001, bound to a specific deployed contract.
func NewVersion001Transactor(address common.Address, transactor bind.ContractTransactor) (*Version001Transactor, error) {
	contract, err := bindVersion001(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &Version001Transactor{contract: contract}, nil
}

// NewVersion001Filterer creates a new log filterer instance of Version001, bound to a specific deployed contract.
func NewVersion001Filterer(address common.Address, filterer bind.ContractFilterer) (*Version001Filterer, error) {
	contract, err := bindVersion001(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &Version001Filterer{contract: contract}, nil
}

// bindVersion001 binds a generic wrapper to an already deployed contract.
func bindVersion001(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(Version001ABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Version001 *Version001Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Version001.Contract.Version001Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Version001 *Version001Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Version001.Contract.Version001Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Version001 *Version001Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Version001.Contract.Version001Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Version001 *Version001CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Version001.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Version001 *Version001TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Version001.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Version001 *Version001TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Version001.Contract.contract.Transact(opts, method, params...)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Version001 *Version001Caller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _Version001.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Version001 *Version001Session) Version() (string, error) {
	return _Version001.Contract.Version(&_Version001.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Version001 *Version001CallerSession) Version() (string, error) {
	return _Version001.Contract.Version(&_Version001.CallOpts)
}

// VersionedMetaData contains all meta data concerning the Versioned contract.
var VersionedMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"version\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"versionString\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"54fd4d50": "version()",
	},
}

// VersionedABI is the input ABI used to generate the binding from.
// Deprecated: Use VersionedMetaData.ABI instead.
var VersionedABI = VersionedMetaData.ABI

// Deprecated: Use VersionedMetaData.Sigs instead.
// VersionedFuncSigs maps the 4-byte function signature to its string representation.
var VersionedFuncSigs = VersionedMetaData.Sigs

// Versioned is an auto generated Go binding around an Ethereum contract.
type Versioned struct {
	VersionedCaller     // Read-only binding to the contract
	VersionedTransactor // Write-only binding to the contract
	VersionedFilterer   // Log filterer for contract events
}

// VersionedCaller is an auto generated read-only Go binding around an Ethereum contract.
type VersionedCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VersionedTransactor is an auto generated write-only Go binding around an Ethereum contract.
type VersionedTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VersionedFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type VersionedFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VersionedSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type VersionedSession struct {
	Contract     *Versioned        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// VersionedCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type VersionedCallerSession struct {
	Contract *VersionedCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// VersionedTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type VersionedTransactorSession struct {
	Contract     *VersionedTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// VersionedRaw is an auto generated low-level Go binding around an Ethereum contract.
type VersionedRaw struct {
	Contract *Versioned // Generic contract binding to access the raw methods on
}

// VersionedCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type VersionedCallerRaw struct {
	Contract *VersionedCaller // Generic read-only contract binding to access the raw methods on
}

// VersionedTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type VersionedTransactorRaw struct {
	Contract *VersionedTransactor // Generic write-only contract binding to access the raw methods on
}

// NewVersioned creates a new instance of Versioned, bound to a specific deployed contract.
func NewVersioned(address common.Address, backend bind.ContractBackend) (*Versioned, error) {
	contract, err := bindVersioned(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Versioned{VersionedCaller: VersionedCaller{contract: contract}, VersionedTransactor: VersionedTransactor{contract: contract}, VersionedFilterer: VersionedFilterer{contract: contract}}, nil
}

// NewVersionedCaller creates a new read-only instance of Versioned, bound to a specific deployed contract.
func NewVersionedCaller(address common.Address, caller bind.ContractCaller) (*VersionedCaller, error) {
	contract, err := bindVersioned(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &VersionedCaller{contract: contract}, nil
}

// NewVersionedTransactor creates a new write-only instance of Versioned, bound to a specific deployed contract.
func NewVersionedTransactor(address common.Address, transactor bind.ContractTransactor) (*VersionedTransactor, error) {
	contract, err := bindVersioned(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &VersionedTransactor{contract: contract}, nil
}

// NewVersionedFilterer creates a new log filterer instance of Versioned, bound to a specific deployed contract.
func NewVersionedFilterer(address common.Address, filterer bind.ContractFilterer) (*VersionedFilterer, error) {
	contract, err := bindVersioned(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &VersionedFilterer{contract: contract}, nil
}

// bindVersioned binds a generic wrapper to an already deployed contract.
func bindVersioned(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(VersionedABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Versioned *VersionedRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Versioned.Contract.VersionedCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Versioned *VersionedRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Versioned.Contract.VersionedTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Versioned *VersionedRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Versioned.Contract.VersionedTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Versioned *VersionedCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Versioned.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Versioned *VersionedTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Versioned.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Versioned *VersionedTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Versioned.Contract.contract.Transact(opts, method, params...)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Versioned *VersionedCaller) Version(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _Versioned.contract.Call(opts, &out, "version")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Versioned *VersionedSession) Version() (string, error) {
	return _Versioned.Contract.Version(&_Versioned.CallOpts)
}

// Version is a free data retrieval call binding the contract method 0x54fd4d50.
//
// Solidity: function version() view returns(string versionString)
func (_Versioned *VersionedCallerSession) Version() (string, error) {
	return _Versioned.Contract.Version(&_Versioned.CallOpts)
}
