package bondingmanager

//go:generate go run github.com/synapsecns/sanguine/tools/abigen generate --sol ../../../packages/contracts-core/flattened/BondingManager.sol --pkg bondingmanager --sol-version 0.8.17 --filename bondingmanager

// here we generate some interfaces we use in for our mocks. TODO this should be automated in abigen for all contracts + be condensed
//go:generate go run github.com/vburenin/ifacemaker -f bondingmanager.abigen.go -s BondingManagerCaller -i IBondingManagerCaller -p bondingmanager -o icaller_generated.go -c "autogenerated file"
//go:generate go run github.com/vburenin/ifacemaker -f bondingmanager.abigen.go -s BondingManagerTransactor -i IBondingManagerTransactor -p bondingmanager -o itransactor_generated.go -c "autogenerated file"
//go:generate go run github.com/vburenin/ifacemaker -f bondingmanager.abigen.go -s BondingManagerFilterer  -i IBondingManagerFilterer  -p bondingmanager  -o filterer_generated.go -c "autogenerated file"
//go:generate go run github.com/vektra/mockery/v2 --name IBondingManager --output ./mocks --case=underscore
// last line must be null
