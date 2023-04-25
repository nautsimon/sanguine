package lightmanager

//go:generate go run github.com/synapsecns/sanguine/tools/abigen generate --sol ../../../packages/contracts-core/flattened/LightManager.sol --pkg lightmanager --sol-version 0.8.17 --filename lightmanager

// here we generate some interfaces we use in for our mocks. TODO this should be automated in abigen for all contracts + be condensed
//go:generate go run github.com/vburenin/ifacemaker -f lightmanager.abigen.go -s LightManagerCaller -i ILightManagerCaller -p lightmanager -o icaller_generated.go -c "autogenerated file"
//go:generate go run github.com/vburenin/ifacemaker -f lightmanager.abigen.go -s LightManagerTransactor -i ILightManagerTransactor -p lightmanager -o itransactor_generated.go -c "autogenerated file"
//go:generate go run github.com/vburenin/ifacemaker -f lightmanager.abigen.go -s LightManagerFilterer  -i ILightManagerFilterer  -p lightmanager  -o filterer_generated.go -c "autogenerated file"
//go:generate go run github.com/vektra/mockery/v2 --name ILightManager --output ./mocks --case=underscore
// last line must be null
