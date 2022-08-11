// autogenerated file

package home

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// IHomeFilterer ...
type IHomeFilterer interface {
	// FilterDispatch is a free log retrieval operation binding the contract event 0x718e547b45036b0526c0cd2f2e3de248b0e8c042c714ecfbee3f5811a5e6e785.
	//
	// Solidity: event Dispatch(bytes32 indexed messageHash, uint256 indexed leafIndex, uint64 indexed destinationAndNonce, bytes tips, bytes message)
	FilterDispatch(opts *bind.FilterOpts, messageHash [][32]byte, leafIndex []*big.Int, destinationAndNonce []uint64) (*HomeDispatchIterator, error)
	// WatchDispatch is a free log subscription operation binding the contract event 0x718e547b45036b0526c0cd2f2e3de248b0e8c042c714ecfbee3f5811a5e6e785.
	//
	// Solidity: event Dispatch(bytes32 indexed messageHash, uint256 indexed leafIndex, uint64 indexed destinationAndNonce, bytes tips, bytes message)
	WatchDispatch(opts *bind.WatchOpts, sink chan<- *HomeDispatch, messageHash [][32]byte, leafIndex []*big.Int, destinationAndNonce []uint64) (event.Subscription, error)
	// ParseDispatch is a log parse operation binding the contract event 0x718e547b45036b0526c0cd2f2e3de248b0e8c042c714ecfbee3f5811a5e6e785.
	//
	// Solidity: event Dispatch(bytes32 indexed messageHash, uint256 indexed leafIndex, uint64 indexed destinationAndNonce, bytes tips, bytes message)
	ParseDispatch(log types.Log) (*HomeDispatch, error)
	// FilterDomainNotaryAdded is a free log retrieval operation binding the contract event 0x7ed5310d8818d06ea4a196771a39a73bf55c815addbf7a52ba87c9be409c3dd1.
	//
	// Solidity: event DomainNotaryAdded(address notary)
	FilterDomainNotaryAdded(opts *bind.FilterOpts) (*HomeDomainNotaryAddedIterator, error)
	// WatchDomainNotaryAdded is a free log subscription operation binding the contract event 0x7ed5310d8818d06ea4a196771a39a73bf55c815addbf7a52ba87c9be409c3dd1.
	//
	// Solidity: event DomainNotaryAdded(address notary)
	WatchDomainNotaryAdded(opts *bind.WatchOpts, sink chan<- *HomeDomainNotaryAdded) (event.Subscription, error)
	// ParseDomainNotaryAdded is a log parse operation binding the contract event 0x7ed5310d8818d06ea4a196771a39a73bf55c815addbf7a52ba87c9be409c3dd1.
	//
	// Solidity: event DomainNotaryAdded(address notary)
	ParseDomainNotaryAdded(log types.Log) (*HomeDomainNotaryAdded, error)
	// FilterDomainNotaryRemoved is a free log retrieval operation binding the contract event 0xe16811bec5badeb0bade36ad31aab1c20f2997b625833474449f893eeecd3bac.
	//
	// Solidity: event DomainNotaryRemoved(address notary)
	FilterDomainNotaryRemoved(opts *bind.FilterOpts) (*HomeDomainNotaryRemovedIterator, error)
	// WatchDomainNotaryRemoved is a free log subscription operation binding the contract event 0xe16811bec5badeb0bade36ad31aab1c20f2997b625833474449f893eeecd3bac.
	//
	// Solidity: event DomainNotaryRemoved(address notary)
	WatchDomainNotaryRemoved(opts *bind.WatchOpts, sink chan<- *HomeDomainNotaryRemoved) (event.Subscription, error)
	// ParseDomainNotaryRemoved is a log parse operation binding the contract event 0xe16811bec5badeb0bade36ad31aab1c20f2997b625833474449f893eeecd3bac.
	//
	// Solidity: event DomainNotaryRemoved(address notary)
	ParseDomainNotaryRemoved(log types.Log) (*HomeDomainNotaryRemoved, error)
	// FilterGuardAdded is a free log retrieval operation binding the contract event 0x93405f05cd04f0d1bd875f2de00f1f3890484ffd0589248953bdfd29ba7f2f59.
	//
	// Solidity: event GuardAdded(address guard)
	FilterGuardAdded(opts *bind.FilterOpts) (*HomeGuardAddedIterator, error)
	// WatchGuardAdded is a free log subscription operation binding the contract event 0x93405f05cd04f0d1bd875f2de00f1f3890484ffd0589248953bdfd29ba7f2f59.
	//
	// Solidity: event GuardAdded(address guard)
	WatchGuardAdded(opts *bind.WatchOpts, sink chan<- *HomeGuardAdded) (event.Subscription, error)
	// ParseGuardAdded is a log parse operation binding the contract event 0x93405f05cd04f0d1bd875f2de00f1f3890484ffd0589248953bdfd29ba7f2f59.
	//
	// Solidity: event GuardAdded(address guard)
	ParseGuardAdded(log types.Log) (*HomeGuardAdded, error)
	// FilterGuardRemoved is a free log retrieval operation binding the contract event 0x59926e0a78d12238b668b31c8e3f6ece235a59a00ede111d883e255b68c4d048.
	//
	// Solidity: event GuardRemoved(address guard)
	FilterGuardRemoved(opts *bind.FilterOpts) (*HomeGuardRemovedIterator, error)
	// WatchGuardRemoved is a free log subscription operation binding the contract event 0x59926e0a78d12238b668b31c8e3f6ece235a59a00ede111d883e255b68c4d048.
	//
	// Solidity: event GuardRemoved(address guard)
	WatchGuardRemoved(opts *bind.WatchOpts, sink chan<- *HomeGuardRemoved) (event.Subscription, error)
	// ParseGuardRemoved is a log parse operation binding the contract event 0x59926e0a78d12238b668b31c8e3f6ece235a59a00ede111d883e255b68c4d048.
	//
	// Solidity: event GuardRemoved(address guard)
	ParseGuardRemoved(log types.Log) (*HomeGuardRemoved, error)
	// FilterImproperAttestation is a free log retrieval operation binding the contract event 0x287e2c0e041ca31a0ce7a1ed8b91a7425b2520880947cdbe778c457ca4c48e5b.
	//
	// Solidity: event ImproperAttestation(address updater, bytes attestation)
	FilterImproperAttestation(opts *bind.FilterOpts) (*HomeImproperAttestationIterator, error)
	// WatchImproperAttestation is a free log subscription operation binding the contract event 0x287e2c0e041ca31a0ce7a1ed8b91a7425b2520880947cdbe778c457ca4c48e5b.
	//
	// Solidity: event ImproperAttestation(address updater, bytes attestation)
	WatchImproperAttestation(opts *bind.WatchOpts, sink chan<- *HomeImproperAttestation) (event.Subscription, error)
	// ParseImproperAttestation is a log parse operation binding the contract event 0x287e2c0e041ca31a0ce7a1ed8b91a7425b2520880947cdbe778c457ca4c48e5b.
	//
	// Solidity: event ImproperAttestation(address updater, bytes attestation)
	ParseImproperAttestation(log types.Log) (*HomeImproperAttestation, error)
	// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
	//
	// Solidity: event Initialized(uint8 version)
	FilterInitialized(opts *bind.FilterOpts) (*HomeInitializedIterator, error)
	// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
	//
	// Solidity: event Initialized(uint8 version)
	WatchInitialized(opts *bind.WatchOpts, sink chan<- *HomeInitialized) (event.Subscription, error)
	// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
	//
	// Solidity: event Initialized(uint8 version)
	ParseInitialized(log types.Log) (*HomeInitialized, error)
	// FilterNewUpdaterManager is a free log retrieval operation binding the contract event 0x958d788fb4c373604cd4c73aa8c592de127d0819b49bb4dc02c8ecd666e965bf.
	//
	// Solidity: event NewUpdaterManager(address updaterManager)
	FilterNewUpdaterManager(opts *bind.FilterOpts) (*HomeNewUpdaterManagerIterator, error)
	// WatchNewUpdaterManager is a free log subscription operation binding the contract event 0x958d788fb4c373604cd4c73aa8c592de127d0819b49bb4dc02c8ecd666e965bf.
	//
	// Solidity: event NewUpdaterManager(address updaterManager)
	WatchNewUpdaterManager(opts *bind.WatchOpts, sink chan<- *HomeNewUpdaterManager) (event.Subscription, error)
	// ParseNewUpdaterManager is a log parse operation binding the contract event 0x958d788fb4c373604cd4c73aa8c592de127d0819b49bb4dc02c8ecd666e965bf.
	//
	// Solidity: event NewUpdaterManager(address updaterManager)
	ParseNewUpdaterManager(log types.Log) (*HomeNewUpdaterManager, error)
	// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
	//
	// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*HomeOwnershipTransferredIterator, error)
	// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
	//
	// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *HomeOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error)
	// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
	//
	// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	ParseOwnershipTransferred(log types.Log) (*HomeOwnershipTransferred, error)
	// FilterUpdaterSlashed is a free log retrieval operation binding the contract event 0x98064af315f26d7333ba107ba43a128ec74345f4d4e6f2549840fe092a1c8bce.
	//
	// Solidity: event UpdaterSlashed(address indexed updater, address indexed reporter)
	FilterUpdaterSlashed(opts *bind.FilterOpts, updater []common.Address, reporter []common.Address) (*HomeUpdaterSlashedIterator, error)
	// WatchUpdaterSlashed is a free log subscription operation binding the contract event 0x98064af315f26d7333ba107ba43a128ec74345f4d4e6f2549840fe092a1c8bce.
	//
	// Solidity: event UpdaterSlashed(address indexed updater, address indexed reporter)
	WatchUpdaterSlashed(opts *bind.WatchOpts, sink chan<- *HomeUpdaterSlashed, updater []common.Address, reporter []common.Address) (event.Subscription, error)
	// ParseUpdaterSlashed is a log parse operation binding the contract event 0x98064af315f26d7333ba107ba43a128ec74345f4d4e6f2549840fe092a1c8bce.
	//
	// Solidity: event UpdaterSlashed(address indexed updater, address indexed reporter)
	ParseUpdaterSlashed(log types.Log) (*HomeUpdaterSlashed, error)
}
