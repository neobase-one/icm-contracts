package localnetworkutils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"time"

	runner_sdk "github.com/ava-labs/avalanche-network-runner/client"
	"github.com/ava-labs/avalanche-network-runner/rpcpb"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/logging"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/subnet-evm/accounts/abi/bind"
	"github.com/ava-labs/subnet-evm/core/types"
	"github.com/ava-labs/subnet-evm/ethclient"
	"github.com/ava-labs/subnet-evm/plugin/evm"
	"github.com/ava-labs/subnet-evm/rpc"
	"github.com/ava-labs/subnet-evm/tests/utils/runner"
	erc20bridge "github.com/ava-labs/teleporter/abi-bindings/go/CrossChainApplications/ERC20Bridge/ERC20Bridge"
	examplecrosschainmessenger "github.com/ava-labs/teleporter/abi-bindings/go/CrossChainApplications/ExampleMessenger/ExampleCrossChainMessenger"
	blockhashpublisher "github.com/ava-labs/teleporter/abi-bindings/go/CrossChainApplications/VerifiedBlockHash/BlockHashPublisher"
	blockhashreceiver "github.com/ava-labs/teleporter/abi-bindings/go/CrossChainApplications/VerifiedBlockHash/BlockHashReceiver"
	exampleerc20 "github.com/ava-labs/teleporter/abi-bindings/go/Mocks/ExampleERC20"
	teleportermessenger "github.com/ava-labs/teleporter/abi-bindings/go/Teleporter/TeleporterMessenger"
	teleporterregistry "github.com/ava-labs/teleporter/abi-bindings/go/Teleporter/upgrades/TeleporterRegistry"
	"github.com/ava-labs/teleporter/tests/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	. "github.com/onsi/gomega"
)

const (
	fundedKeyStr = "56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027"
)

var (
	teleporterContractAddress common.Address
	subnetA, subnetB, subnetC ids.ID
	subnetsInfo               map[ids.ID]*utils.SubnetTestInfo = make(map[ids.ID]*utils.SubnetTestInfo)
	subnetNodeNames           map[ids.ID][]string              = make(map[ids.ID][]string)

	globalFundedKey *ecdsa.PrivateKey

	// Internal vars only used to set up the local network
	anrClient           runner_sdk.Client
	manager             *runner.NetworkManager
	warpChainConfigPath string
)

//
// Global test state getters. Should be called within a test spec, after SetupNetwork has been called
//

func GetSubnetsInfo() []utils.SubnetTestInfo {
	return []utils.SubnetTestInfo{
		*subnetsInfo[subnetA],
		*subnetsInfo[subnetB],
		*subnetsInfo[subnetC],
	}
}

func GetTeleporterContractAddress() common.Address {
	return teleporterContractAddress
}
func GetFundedAccountInfo() (common.Address, *ecdsa.PrivateKey) {
	fundedAddress := crypto.PubkeyToAddress(globalFundedKey.PublicKey)
	return fundedAddress, globalFundedKey
}

// SetupNetwork starts the default network and adds 10 new nodes as validators with BLS keys
// registered on the P-Chain.
// Adds two disjoint sets of 5 of the new validator nodes to validate two new subnets with a
// a single Subnet-EVM blockchain.
func SetupNetwork(warpGenesisFile string) {
	ctx := context.Background()
	var err error

	// Name 10 new validators (which should have BLS key registered)
	var subnetANodeNames []string
	var subnetBNodeNames []string
	var subnetCNodeNames []string
	for i := 1; i <= 15; i++ {
		n := fmt.Sprintf("node%d-bls", i)
		if i <= 5 {
			subnetANodeNames = append(subnetANodeNames, n)
		} else if i <= 10 {
			subnetBNodeNames = append(subnetBNodeNames, n)
		} else {
			subnetCNodeNames = append(subnetCNodeNames, n)
		}
	}

	f, err := os.CreateTemp(os.TempDir(), "config.json")
	Expect(err).Should(BeNil())
	_, err = f.Write([]byte(`{"warp-api-enabled": true}`))
	Expect(err).Should(BeNil())
	warpChainConfigPath = f.Name()

	// Make sure that the warp genesis file exists
	_, err = os.Stat(warpGenesisFile)
	Expect(err).Should(BeNil())

	anrConfig := runner.NewDefaultANRConfig()
	log.Info("dbg", "anrConfig", anrConfig)
	manager = runner.NewNetworkManager(anrConfig)

	// Construct the network using the avalanche-network-runner
	_, err = manager.StartDefaultNetwork(ctx)
	Expect(err).Should(BeNil())
	err = manager.SetupNetwork(
		ctx,
		anrConfig.AvalancheGoExecPath,
		[]*rpcpb.BlockchainSpec{
			{
				VmName:      evm.IDStr,
				Genesis:     warpGenesisFile,
				ChainConfig: warpChainConfigPath,
				SubnetSpec: &rpcpb.SubnetSpec{
					SubnetConfig: "",
					Participants: subnetANodeNames,
				},
			},
			{
				VmName:      evm.IDStr,
				Genesis:     warpGenesisFile,
				ChainConfig: warpChainConfigPath,
				SubnetSpec: &rpcpb.SubnetSpec{
					SubnetConfig: "",
					Participants: subnetBNodeNames,
				},
			},
			{
				VmName:      evm.IDStr,
				Genesis:     warpGenesisFile,
				ChainConfig: warpChainConfigPath,
				SubnetSpec: &rpcpb.SubnetSpec{
					SubnetConfig: "",
					Participants: subnetCNodeNames,
				},
			},
		},
	)
	Expect(err).Should(BeNil())

	// Issue transactions to activate the proposerVM fork on the chains
	globalFundedKey, err = crypto.HexToECDSA(fundedKeyStr)
	Expect(err).Should(BeNil())
	SetupProposerVM(ctx, globalFundedKey, manager, 0)
	SetupProposerVM(ctx, globalFundedKey, manager, 1)
	SetupProposerVM(ctx, globalFundedKey, manager, 2)

	// Create the ANR client
	logLevel, err := logging.ToLevel("info")
	Expect(err).Should(BeNil())

	logFactory := logging.NewFactory(logging.Config{
		DisplayLevel: logLevel,
		LogLevel:     logLevel,
	})
	zapLog, err := logFactory.Make("main")
	Expect(err).Should(BeNil())

	anrClient, err = runner_sdk.New(runner_sdk.Config{
		Endpoint:    "0.0.0.0:12352",
		DialTimeout: 10 * time.Second,
	}, zapLog)
	Expect(err).Should(BeNil())

	// On initial startup, we need to first set the subnet node names
	// before calling setSubnetValues for the two subnets
	subnetIDs := manager.GetSubnets()
	Expect(len(subnetIDs)).Should(Equal(3))
	subnetA = subnetIDs[0]
	subnetB = subnetIDs[1]
	subnetC = subnetIDs[2]

	subnetNodeNames[subnetA] = subnetANodeNames
	subnetNodeNames[subnetB] = subnetBNodeNames
	subnetNodeNames[subnetC] = subnetCNodeNames

	setSubnetValues(subnetA)
	setSubnetValues(subnetB)
	setSubnetValues(subnetC)

	log.Info("Finished setting up e2e test subnet variables")
}

func SetSubnetValues() {
	subnetIDs := manager.GetSubnets()
	Expect(len(subnetIDs)).Should(Equal(3))

	subnetA = subnetIDs[0]
	setSubnetValues(subnetA)

	subnetB = subnetIDs[1]
	setSubnetValues(subnetB)

	subnetC = subnetIDs[2]
	setSubnetValues(subnetC)
}

func setSubnetValues(subnetID ids.ID) {
	subnetDetails, ok := manager.GetSubnet(subnetID)
	Expect(ok).Should(BeTrue())
	blockchainID := subnetDetails.BlockchainID

	// Reset the validator URIs, as they may have changed
	subnetDetails.ValidatorURIs = nil
	status, err := anrClient.Status(context.Background())
	Expect(err).Should(BeNil())
	nodeInfos := status.GetClusterInfo().GetNodeInfos()

	for _, nodeName := range subnetNodeNames[subnetID] {
		subnetDetails.ValidatorURIs = append(subnetDetails.ValidatorURIs, nodeInfos[nodeName].Uri)
	}
	var chainNodeURIs []string
	chainNodeURIs = append(chainNodeURIs, subnetDetails.ValidatorURIs...)

	chainWSURI := utils.HttpToWebsocketURI(chainNodeURIs[0], blockchainID.String())
	chainRPCURI := utils.HttpToRPCURI(chainNodeURIs[0], blockchainID.String())

	if subnetsInfo[subnetID] != nil && subnetsInfo[subnetID].ChainWSClient != nil {
		subnetsInfo[subnetID].ChainWSClient.Close()
	}
	chainWSClient, err := ethclient.Dial(chainWSURI)
	Expect(err).Should(BeNil())
	if subnetsInfo[subnetID] != nil && subnetsInfo[subnetID].ChainRPCClient != nil {
		subnetsInfo[subnetID].ChainRPCClient.Close()
	}
	chainRPCClient, err := ethclient.Dial(chainRPCURI)
	Expect(err).Should(BeNil())
	chainIDInt, err := chainRPCClient.ChainID(context.Background())
	Expect(err).Should(BeNil())

	// Set the new values in the subnetsInfo map
	if subnetsInfo[subnetID] == nil {
		subnetsInfo[subnetID] = &utils.SubnetTestInfo{}
	}
	subnetsInfo[subnetID].SubnetID = subnetID
	subnetsInfo[subnetID].BlockchainID = blockchainID
	subnetsInfo[subnetID].ChainNodeURIs = chainNodeURIs
	subnetsInfo[subnetID].ChainWSClient = chainWSClient
	subnetsInfo[subnetID].ChainRPCClient = chainRPCClient
	subnetsInfo[subnetID].ChainIDInt = chainIDInt

	// TeleporterMessenger is set in DeployTeleporterContracts
	// TeleporterRegistryAddress is set in DeployTeleporterRegistryContracts
}

// DeployTeleporterContracts deploys the Teleporter contract to all subnets.
// The caller is responsible for generating the deployment transaction information
func DeployTeleporterContracts(
	transactionBytes []byte,
	deployerAddress common.Address,
	contractAddress common.Address,
	fundedKey *ecdsa.PrivateKey,
) {
	log.Info("Deploying Teleporter contract to subnets")

	subnetsInfoList := GetSubnetsInfo()

	// Set the package level teleporterContractAddress
	teleporterContractAddress = contractAddress

	ctx := context.Background()

	for _, subnetInfo := range subnetsInfoList {
		// Fund the deployer address
		{
			fundAmount := big.NewInt(0).Mul(big.NewInt(1e18), big.NewInt(10)) // 10eth
			fundDeployerTx := utils.CreateNativeTransferTransaction(
				ctx, subnetInfo, fundedKey, deployerAddress, fundAmount,
			)
			utils.SendTransactionAndWaitForAcceptance(ctx, subnetInfo, fundDeployerTx, true)
		}
		log.Info("Finished funding Teleporter deployer", "blockchainID", subnetInfo.BlockchainID.Hex())

		// Deploy Teleporter contract
		{
			rpcClient, err := rpc.DialContext(
				ctx,
				utils.HttpToRPCURI(subnetInfo.ChainNodeURIs[0], subnetInfo.BlockchainID.String()),
			)
			Expect(err).Should(BeNil())
			defer rpcClient.Close()

			newHeads := make(chan *types.Header, 10)
			sub, err := subnetInfo.ChainWSClient.SubscribeNewHead(ctx, newHeads)
			Expect(err).Should(BeNil())
			defer sub.Unsubscribe()

			err = rpcClient.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(transactionBytes))
			Expect(err).Should(BeNil())

			<-newHeads
			teleporterCode, err := subnetInfo.ChainRPCClient.CodeAt(ctx, teleporterContractAddress, nil)
			Expect(err).Should(BeNil())
			Expect(len(teleporterCode)).Should(BeNumerically(">", 2)) // 0x is an EOA, contract returns the bytecode
		}
		teleporterMessenger, err := teleportermessenger.NewTeleporterMessenger(
			teleporterContractAddress, subnetInfo.ChainRPCClient,
		)
		Expect(err).Should(BeNil())
		subnetsInfo[subnetInfo.SubnetID].TeleporterMessenger = teleporterMessenger
		log.Info("Finished deploying Teleporter contract", "blockchainID", subnetInfo.BlockchainID.Hex())
	}
	log.Info("Deployed Teleporter contracts to all subnets")
}

func DeployTeleporterRegistryContracts(
	teleporterAddress common.Address,
	deployerKey *ecdsa.PrivateKey,
) {
	log.Info("Deploying TeleporterRegistry contract to subnets")
	ctx := context.Background()

	entries := []teleporterregistry.ProtocolRegistryEntry{
		{
			Version:         big.NewInt(1),
			ProtocolAddress: teleporterAddress,
		},
	}

	for _, subnetInfo := range GetSubnetsInfo() {
		opts, err := bind.NewKeyedTransactorWithChainID(deployerKey, subnetInfo.ChainIDInt)
		Expect(err).Should(BeNil())
		teleporterRegistryAddress, tx, _, err := teleporterregistry.DeployTeleporterRegistry(
			opts, subnetInfo.ChainRPCClient, entries,
		)
		Expect(err).Should(BeNil())

		subnetsInfo[subnetInfo.SubnetID].TeleporterRegistryAddress = teleporterRegistryAddress
		// Wait for the transaction to be mined
		receipt, err := bind.WaitMined(ctx, subnetInfo.ChainRPCClient, tx)
		Expect(err).Should(BeNil())
		Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))
		log.Info("Deployed TeleporterRegistry contract to subnet", subnetInfo.SubnetID.Hex(),
			"Deploy address", teleporterRegistryAddress.Hex())
	}

	log.Info("Deployed TeleporterRegistry contracts to all subnets")
}

func DeployExampleERC20(
	ctx context.Context,
	fundedKey *ecdsa.PrivateKey,
	source utils.SubnetTestInfo,
) (common.Address, *exampleerc20.ExampleERC20) {
	opts, err := bind.NewKeyedTransactorWithChainID(fundedKey, source.ChainIDInt)
	Expect(err).Should(BeNil())

	// Deploy Mock ERC20 contract
	address, txn, token, err := exampleerc20.DeployExampleERC20(opts, source.ChainRPCClient)
	Expect(err).Should(BeNil())
	log.Info("Deployed Mock ERC20 contract", "address", address.Hex(), "txHash", txn.Hash().Hex())

	// Wait for the transaction to be mined
	receipt, err := bind.WaitMined(ctx, source.ChainRPCClient, txn)
	Expect(err).Should(BeNil())
	Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))

	return address, token
}

func DeployExampleCrossChainMessenger(
	ctx context.Context,
	deployerKey *ecdsa.PrivateKey,
	subnet utils.SubnetTestInfo,
) (common.Address, *examplecrosschainmessenger.ExampleCrossChainMessenger) {
	opts, err := bind.NewKeyedTransactorWithChainID(
		deployerKey, subnet.ChainIDInt)
	Expect(err).Should(BeNil())
	address, tx, exampleMessenger, err := examplecrosschainmessenger.DeployExampleCrossChainMessenger(
		opts, subnet.ChainRPCClient, subnet.TeleporterRegistryAddress,
	)
	Expect(err).Should(BeNil())

	// Wait for the transaction to be mined
	receipt, err := bind.WaitMined(ctx, subnet.ChainRPCClient, tx)
	Expect(err).Should(BeNil())
	Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))

	return address, exampleMessenger
}

func DeployERC20Bridge(
	ctx context.Context,
	fundedKey *ecdsa.PrivateKey,
	source utils.SubnetTestInfo,
) (common.Address, *erc20bridge.ERC20Bridge) {
	opts, err := bind.NewKeyedTransactorWithChainID(fundedKey, source.ChainIDInt)
	Expect(err).Should(BeNil())
	address, tx, erc20Bridge, err := erc20bridge.DeployERC20Bridge(
		opts, source.ChainRPCClient, source.TeleporterRegistryAddress,
	)
	Expect(err).Should(BeNil())

	// Wait for the transaction to be mined
	receipt, err := bind.WaitMined(ctx, source.ChainRPCClient, tx)
	Expect(err).Should(BeNil())
	Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))

	log.Info("Deployed ERC20 Bridge contract", "address", address.Hex(), "txHash", tx.Hash().Hex())

	return address, erc20Bridge
}

func DeployBlockHashPublisher(
	ctx context.Context,
	deployerKey *ecdsa.PrivateKey,
	subnet utils.SubnetTestInfo,
) (common.Address, *blockhashpublisher.BlockHashPublisher) {
	opts, err := bind.NewKeyedTransactorWithChainID(
		deployerKey, subnet.ChainIDInt)
	Expect(err).Should(BeNil())
	address, tx, publisher, err := blockhashpublisher.DeployBlockHashPublisher(
		opts, subnet.ChainRPCClient, subnet.TeleporterRegistryAddress,
	)
	Expect(err).Should(BeNil())

	// Wait for the transaction to be mined
	receipt, err := bind.WaitMined(ctx, subnet.ChainRPCClient, tx)
	Expect(err).Should(BeNil())
	Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))

	return address, publisher
}

func DeployBlockHashReceiver(
	ctx context.Context,
	deployerKey *ecdsa.PrivateKey,
	subnet utils.SubnetTestInfo,
	publisherAddress common.Address,
	publisherChainID [32]byte,
) (common.Address, *blockhashreceiver.BlockHashReceiver) {
	opts, err := bind.NewKeyedTransactorWithChainID(
		deployerKey, subnet.ChainIDInt)
	Expect(err).Should(BeNil())
	address, tx, receiver, err := blockhashreceiver.DeployBlockHashReceiver(
		opts,
		subnet.ChainRPCClient,
		subnet.TeleporterRegistryAddress,
		publisherChainID,
		publisherAddress,
	)
	Expect(err).Should(BeNil())

	// Wait for the transaction to be mined
	receipt, err := bind.WaitMined(ctx, subnet.ChainRPCClient, tx)
	Expect(err).Should(BeNil())
	Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))

	return address, receiver
}

func ExampleERC20Approve(
	ctx context.Context,
	token *exampleerc20.ExampleERC20,
	spender common.Address,
	amount *big.Int,
	source utils.SubnetTestInfo,
	fundedKey *ecdsa.PrivateKey,
) {
	opts, err := bind.NewKeyedTransactorWithChainID(fundedKey, source.ChainIDInt)
	Expect(err).Should(BeNil())
	txn, err := token.Approve(opts, spender, amount)
	Expect(err).Should(BeNil())
	log.Info("Approved Mock ERC20", "spender", teleporterContractAddress.Hex(), "txHash", txn.Hash().Hex())

	receipt, err := bind.WaitMined(ctx, source.ChainRPCClient, txn)
	Expect(err).Should(BeNil())
	Expect(receipt.Status).Should(Equal(types.ReceiptStatusSuccessful))
}

func TearDownNetwork() {
	log.Info("Tearing down network")
	Expect(manager).ShouldNot(BeNil())
	Expect(manager.TeardownNetwork()).Should(BeNil())
	Expect(os.Remove(warpChainConfigPath)).Should(BeNil())
}

func RemoveSubnetValidators(ctx context.Context, subnetID ids.ID, nodeNames []string) {
	_, err := anrClient.RemoveSubnetValidator(ctx, []*rpcpb.RemoveSubnetValidatorSpec{
		{
			SubnetId:  subnetID.String(),
			NodeNames: nodeNames,
		},
	})
	Expect(err).Should(BeNil())

	// Remove the node names
	currNodes := set.NewSet[string](len(subnetNodeNames[subnetID]))
	currNodes.Add(subnetNodeNames[subnetID]...)
	currNodes.Remove(nodeNames...)
	subnetNodeNames[subnetID] = currNodes.List()

	SetSubnetValues()
}

func AddSubnetValidators(ctx context.Context, subnetID ids.ID, nodeNames []string) {
	_, err := anrClient.AddSubnetValidators(ctx, []*rpcpb.SubnetValidatorsSpec{
		{
			SubnetId:  subnetID.String(),
			NodeNames: nodeNames,
		},
	})
	Expect(err).Should(BeNil())

	// Add the new node names
	subnetNodeNames[subnetID] = append(subnetNodeNames[subnetID], nodeNames...)

	SetSubnetValues()
}

func RestartNodes(ctx context.Context, nodeNames []string) {
	for _, nodeName := range nodeNames {
		_, err := anrClient.RestartNode(ctx, nodeName)
		Expect(err).Should(BeNil())
	}
	SetSubnetValues()
}