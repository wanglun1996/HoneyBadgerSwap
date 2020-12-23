package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	GOPATH		= os.Getenv("GOPATH")
	minBalance	= big.NewInt(200000000000000000)

	//parameter for private net
	//HttpEndpoint	= "http://127.0.0.1:8545"
	//WsEndpoint		= "ws://127.0.0.1:8546"
	//EthAddr 		= common.HexToAddress("0x0")
	//HbswapAddr 		= common.HexToAddress("0xF74Eb25Ab1785D24306CA6b3CBFf0D0b0817C5E2")
	//TokenAddr 		= common.HexToAddress("0x6b5c9637e0207c72Ee1a275b6C3b686ba8D87385")
	//chainID 		= "123"

	//parameter for kovan test net
	chainID			= "42"
	HttpEndpoint	= "https://kovan.infura.io/v3/6a82d2519efb4d748c02552e02e369c1"
	WsEndpoint		= "wss://kovan.infura.io/ws/v3/6a82d2519efb4d748c02552e02e369c1"
	EthAddr 		= common.HexToAddress("0x0")
	HbswapAddr 		= common.HexToAddress("0x6b5c9637e0207c72Ee1a275b6C3b686ba8D87385")
	TokenAddr 		= common.HexToAddress("0x8C89e5D2bCc0e4C26E3295d48d052E11bd03C06A")
)

func ExecCmd(cmd *exec.Cmd) string {
	fmt.Println(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("err:\n%s\n", stderr.String())
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
	fmt.Printf("out:\n%s\n", stdout.String())
	return stdout.String()
}

func StrToBig(st string) *big.Int {
	v, _ := new(big.Int).SetString(st, 10)
	return v
}

func GetEthClient(ethInstance string) (*ethclient.Client) {
	conn, err := ethclient.Dial(ethInstance)
	if err != nil {
		log.Fatal(err)
	}

	return conn
}

func GetAccount(account string) (*bind.TransactOpts) {
	dir := GOPATH + "/src/github.com/initc3/MP-SPDZ/Scripts/hbswap/poa/keystore/" + account + "/"

	list, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	var name string
	for _, info := range list {
		name = info.Name()
		if err != nil {
			log.Fatal(err)
		}
	}

	bytes, err := ioutil.ReadFile(dir + name)
	if err != nil {
		log.Fatal(err)
	}

	password := ""
	auth, err := bind.NewTransactor(strings.NewReader(string(bytes)), password)
	if err != nil {
		log.Fatal(err)
	}

	auth.GasLimit = 8000000

	return auth
}

func WaitMined(ctx context.Context, ec *ethclient.Client,
	tx *types.Transaction, blockDelay uint64) (*types.Receipt, error) {
	const missingFieldErr = "missing required field 'transactionHash' for Log"

	if ec == nil {
		return nil, errors.New("nil ethclient")
	}
	queryTicker := time.NewTicker(time.Second)
	defer queryTicker.Stop()
	txHashBytes := common.HexToHash(tx.Hash().Hex())
	for {
		receipt, rerr := ec.TransactionReceipt(ctx, txHashBytes)
		if rerr == nil {
			if blockDelay == 0 {
				return receipt, rerr
			}
			break
		} else if rerr == ethereum.NotFound || rerr.Error() == missingFieldErr {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-queryTicker.C:
			}
		} else {
			return receipt, rerr
		}
	}
	ddl := big.NewInt(0)
	latestBlockHeader, err := ec.HeaderByNumber(ctx, nil)
	if err == nil {
		ddl.Add(new(big.Int).SetUint64(blockDelay), latestBlockHeader.Number)
	}
	for {
		latestBlockHeader, err := ec.HeaderByNumber(ctx, nil)
		if err == nil && ddl.Cmp(latestBlockHeader.Number) < 0 {
			receipt, rerr := ec.TransactionReceipt(ctx, txHashBytes)
			if rerr == nil {
				log.Println("tx confirmed!")
				return receipt, rerr
			} else if rerr == ethereum.NotFound || rerr.Error() == missingFieldErr {
				return nil, errors.New("tx is dropped due to chain re-org")
			} else {
				return receipt, rerr
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}

func stringToBigInt(v string) (*big.Int) {
	value := big.NewInt(0)
	value.SetString(v, 10)
	return value
}