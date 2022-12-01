// autogenerated file

package origin

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// IOriginFilterer ...
type IOriginFilterer interface {
	// FilterAttestationAccepted is a free log retrieval operation binding the contract event 0x744faabf74c86a873d8f8256c1f071b7ac997f1a9fa1f506dc5a528d5bbb16f3.
	//
	// Solidity: event AttestationAccepted(address indexed notary, bytes attestation)
	FilterAttestationAccepted(opts *bind.FilterOpts, notary []common.Address) (*OriginAttestationAcceptedIterator, error)
	// WatchAttestationAccepted is a free log subscription operation binding the contract event 0x744faabf74c86a873d8f8256c1f071b7ac997f1a9fa1f506dc5a528d5bbb16f3.
	//
	// Solidity: event AttestationAccepted(address indexed notary, bytes attestation)
	WatchAttestationAccepted(opts *bind.WatchOpts, sink chan<- *OriginAttestationAccepted, notary []common.Address) (event.Subscription, error)
	// ParseAttestationAccepted is a log parse operation binding the contract event 0x744faabf74c86a873d8f8256c1f071b7ac997f1a9fa1f506dc5a528d5bbb16f3.
	//
	// Solidity: event AttestationAccepted(address indexed notary, bytes attestation)
	ParseAttestationAccepted(log types.Log) (*OriginAttestationAccepted, error)
	// FilterCorrectFraudReport is a free log retrieval operation binding the contract event 0xa0248f358d0f7bb4c63d2bd5a3e521bb7aba00ccfde9442154e4950711a912f8.
	//
	// Solidity: event CorrectFraudReport(address indexed guard, bytes report)
	FilterCorrectFraudReport(opts *bind.FilterOpts, guard []common.Address) (*OriginCorrectFraudReportIterator, error)
	// WatchCorrectFraudReport is a free log subscription operation binding the contract event 0xa0248f358d0f7bb4c63d2bd5a3e521bb7aba00ccfde9442154e4950711a912f8.
	//
	// Solidity: event CorrectFraudReport(address indexed guard, bytes report)
	WatchCorrectFraudReport(opts *bind.WatchOpts, sink chan<- *OriginCorrectFraudReport, guard []common.Address) (event.Subscription, error)
	// ParseCorrectFraudReport is a log parse operation binding the contract event 0xa0248f358d0f7bb4c63d2bd5a3e521bb7aba00ccfde9442154e4950711a912f8.
	//
	// Solidity: event CorrectFraudReport(address indexed guard, bytes report)
	ParseCorrectFraudReport(log types.Log) (*OriginCorrectFraudReport, error)
	// FilterDispatch is a free log retrieval operation binding the contract event 0xada9f9f4bf16282091ddc28e7d70838404cd5bdff1b87d8650339e8d02b7753d.
	//
	// Solidity: event Dispatch(bytes32 indexed messageHash, uint32 indexed nonce, uint32 indexed destination, bytes tips, bytes message)
	FilterDispatch(opts *bind.FilterOpts, messageHash [][32]byte, nonce []uint32, destination []uint32) (*OriginDispatchIterator, error)
	// WatchDispatch is a free log subscription operation binding the contract event 0xada9f9f4bf16282091ddc28e7d70838404cd5bdff1b87d8650339e8d02b7753d.
	//
	// Solidity: event Dispatch(bytes32 indexed messageHash, uint32 indexed nonce, uint32 indexed destination, bytes tips, bytes message)
	WatchDispatch(opts *bind.WatchOpts, sink chan<- *OriginDispatch, messageHash [][32]byte, nonce []uint32, destination []uint32) (event.Subscription, error)
	// ParseDispatch is a log parse operation binding the contract event 0xada9f9f4bf16282091ddc28e7d70838404cd5bdff1b87d8650339e8d02b7753d.
	//
	// Solidity: event Dispatch(bytes32 indexed messageHash, uint32 indexed nonce, uint32 indexed destination, bytes tips, bytes message)
	ParseDispatch(log types.Log) (*OriginDispatch, error)
	// FilterFraudAttestation is a free log retrieval operation binding the contract event 0xa458d78fa8902ff24cc896d608e762eb06543f0541124e5582e928e1e4789423.
	//
	// Solidity: event FraudAttestation(address indexed notary, bytes attestation)
	FilterFraudAttestation(opts *bind.FilterOpts, notary []common.Address) (*OriginFraudAttestationIterator, error)
	// WatchFraudAttestation is a free log subscription operation binding the contract event 0xa458d78fa8902ff24cc896d608e762eb06543f0541124e5582e928e1e4789423.
	//
	// Solidity: event FraudAttestation(address indexed notary, bytes attestation)
	WatchFraudAttestation(opts *bind.WatchOpts, sink chan<- *OriginFraudAttestation, notary []common.Address) (event.Subscription, error)
	// ParseFraudAttestation is a log parse operation binding the contract event 0xa458d78fa8902ff24cc896d608e762eb06543f0541124e5582e928e1e4789423.
	//
	// Solidity: event FraudAttestation(address indexed notary, bytes attestation)
	ParseFraudAttestation(log types.Log) (*OriginFraudAttestation, error)
	// FilterGuardAdded is a free log retrieval operation binding the contract event 0x93405f05cd04f0d1bd875f2de00f1f3890484ffd0589248953bdfd29ba7f2f59.
	//
	// Solidity: event GuardAdded(address guard)
	FilterGuardAdded(opts *bind.FilterOpts) (*OriginGuardAddedIterator, error)
	// WatchGuardAdded is a free log subscription operation binding the contract event 0x93405f05cd04f0d1bd875f2de00f1f3890484ffd0589248953bdfd29ba7f2f59.
	//
	// Solidity: event GuardAdded(address guard)
	WatchGuardAdded(opts *bind.WatchOpts, sink chan<- *OriginGuardAdded) (event.Subscription, error)
	// ParseGuardAdded is a log parse operation binding the contract event 0x93405f05cd04f0d1bd875f2de00f1f3890484ffd0589248953bdfd29ba7f2f59.
	//
	// Solidity: event GuardAdded(address guard)
	ParseGuardAdded(log types.Log) (*OriginGuardAdded, error)
	// FilterGuardRemoved is a free log retrieval operation binding the contract event 0x59926e0a78d12238b668b31c8e3f6ece235a59a00ede111d883e255b68c4d048.
	//
	// Solidity: event GuardRemoved(address guard)
	FilterGuardRemoved(opts *bind.FilterOpts) (*OriginGuardRemovedIterator, error)
	// WatchGuardRemoved is a free log subscription operation binding the contract event 0x59926e0a78d12238b668b31c8e3f6ece235a59a00ede111d883e255b68c4d048.
	//
	// Solidity: event GuardRemoved(address guard)
	WatchGuardRemoved(opts *bind.WatchOpts, sink chan<- *OriginGuardRemoved) (event.Subscription, error)
	// ParseGuardRemoved is a log parse operation binding the contract event 0x59926e0a78d12238b668b31c8e3f6ece235a59a00ede111d883e255b68c4d048.
	//
	// Solidity: event GuardRemoved(address guard)
	ParseGuardRemoved(log types.Log) (*OriginGuardRemoved, error)
	// FilterGuardSlashed is a free log retrieval operation binding the contract event 0xf2b3869e9727d6dfa6823415649eb18a3bbb7cf9aa2af02af10aaf8d10e14095.
	//
	// Solidity: event GuardSlashed(address indexed guard, address indexed reporter)
	FilterGuardSlashed(opts *bind.FilterOpts, guard []common.Address, reporter []common.Address) (*OriginGuardSlashedIterator, error)
	// WatchGuardSlashed is a free log subscription operation binding the contract event 0xf2b3869e9727d6dfa6823415649eb18a3bbb7cf9aa2af02af10aaf8d10e14095.
	//
	// Solidity: event GuardSlashed(address indexed guard, address indexed reporter)
	WatchGuardSlashed(opts *bind.WatchOpts, sink chan<- *OriginGuardSlashed, guard []common.Address, reporter []common.Address) (event.Subscription, error)
	// ParseGuardSlashed is a log parse operation binding the contract event 0xf2b3869e9727d6dfa6823415649eb18a3bbb7cf9aa2af02af10aaf8d10e14095.
	//
	// Solidity: event GuardSlashed(address indexed guard, address indexed reporter)
	ParseGuardSlashed(log types.Log) (*OriginGuardSlashed, error)
	// FilterIncorrectReport is a free log retrieval operation binding the contract event 0x36670329f075c374c3847f464e4acdaa51fc70c69c52cb8317787b237088ec63.
	//
	// Solidity: event IncorrectReport(address indexed guard, bytes report)
	FilterIncorrectReport(opts *bind.FilterOpts, guard []common.Address) (*OriginIncorrectReportIterator, error)
	// WatchIncorrectReport is a free log subscription operation binding the contract event 0x36670329f075c374c3847f464e4acdaa51fc70c69c52cb8317787b237088ec63.
	//
	// Solidity: event IncorrectReport(address indexed guard, bytes report)
	WatchIncorrectReport(opts *bind.WatchOpts, sink chan<- *OriginIncorrectReport, guard []common.Address) (event.Subscription, error)
	// ParseIncorrectReport is a log parse operation binding the contract event 0x36670329f075c374c3847f464e4acdaa51fc70c69c52cb8317787b237088ec63.
	//
	// Solidity: event IncorrectReport(address indexed guard, bytes report)
	ParseIncorrectReport(log types.Log) (*OriginIncorrectReport, error)
	// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
	//
	// Solidity: event Initialized(uint8 version)
	FilterInitialized(opts *bind.FilterOpts) (*OriginInitializedIterator, error)
	// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
	//
	// Solidity: event Initialized(uint8 version)
	WatchInitialized(opts *bind.WatchOpts, sink chan<- *OriginInitialized) (event.Subscription, error)
	// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
	//
	// Solidity: event Initialized(uint8 version)
	ParseInitialized(log types.Log) (*OriginInitialized, error)
	// FilterNotaryAdded is a free log retrieval operation binding the contract event 0x62d8d15324cce2626119bb61d595f59e655486b1ab41b52c0793d814fe03c355.
	//
	// Solidity: event NotaryAdded(uint32 indexed domain, address notary)
	FilterNotaryAdded(opts *bind.FilterOpts, domain []uint32) (*OriginNotaryAddedIterator, error)
	// WatchNotaryAdded is a free log subscription operation binding the contract event 0x62d8d15324cce2626119bb61d595f59e655486b1ab41b52c0793d814fe03c355.
	//
	// Solidity: event NotaryAdded(uint32 indexed domain, address notary)
	WatchNotaryAdded(opts *bind.WatchOpts, sink chan<- *OriginNotaryAdded, domain []uint32) (event.Subscription, error)
	// ParseNotaryAdded is a log parse operation binding the contract event 0x62d8d15324cce2626119bb61d595f59e655486b1ab41b52c0793d814fe03c355.
	//
	// Solidity: event NotaryAdded(uint32 indexed domain, address notary)
	ParseNotaryAdded(log types.Log) (*OriginNotaryAdded, error)
	// FilterNotaryRemoved is a free log retrieval operation binding the contract event 0x3e006f5b97c04e82df349064761281b0981d45330c2f3e57cc032203b0e31b6b.
	//
	// Solidity: event NotaryRemoved(uint32 indexed domain, address notary)
	FilterNotaryRemoved(opts *bind.FilterOpts, domain []uint32) (*OriginNotaryRemovedIterator, error)
	// WatchNotaryRemoved is a free log subscription operation binding the contract event 0x3e006f5b97c04e82df349064761281b0981d45330c2f3e57cc032203b0e31b6b.
	//
	// Solidity: event NotaryRemoved(uint32 indexed domain, address notary)
	WatchNotaryRemoved(opts *bind.WatchOpts, sink chan<- *OriginNotaryRemoved, domain []uint32) (event.Subscription, error)
	// ParseNotaryRemoved is a log parse operation binding the contract event 0x3e006f5b97c04e82df349064761281b0981d45330c2f3e57cc032203b0e31b6b.
	//
	// Solidity: event NotaryRemoved(uint32 indexed domain, address notary)
	ParseNotaryRemoved(log types.Log) (*OriginNotaryRemoved, error)
	// FilterNotarySlashed is a free log retrieval operation binding the contract event 0x70f97c2b606c3d7af38fff3f924c8396f5a05d266b5dc523d863ad27a1d7518a.
	//
	// Solidity: event NotarySlashed(address indexed notary, address indexed guard, address indexed reporter)
	FilterNotarySlashed(opts *bind.FilterOpts, notary []common.Address, guard []common.Address, reporter []common.Address) (*OriginNotarySlashedIterator, error)
	// WatchNotarySlashed is a free log subscription operation binding the contract event 0x70f97c2b606c3d7af38fff3f924c8396f5a05d266b5dc523d863ad27a1d7518a.
	//
	// Solidity: event NotarySlashed(address indexed notary, address indexed guard, address indexed reporter)
	WatchNotarySlashed(opts *bind.WatchOpts, sink chan<- *OriginNotarySlashed, notary []common.Address, guard []common.Address, reporter []common.Address) (event.Subscription, error)
	// ParseNotarySlashed is a log parse operation binding the contract event 0x70f97c2b606c3d7af38fff3f924c8396f5a05d266b5dc523d863ad27a1d7518a.
	//
	// Solidity: event NotarySlashed(address indexed notary, address indexed guard, address indexed reporter)
	ParseNotarySlashed(log types.Log) (*OriginNotarySlashed, error)
	// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
	//
	// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*OriginOwnershipTransferredIterator, error)
	// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
	//
	// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *OriginOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error)
	// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
	//
	// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
	ParseOwnershipTransferred(log types.Log) (*OriginOwnershipTransferred, error)
}
