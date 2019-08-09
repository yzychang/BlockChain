package com.example.demo;

import com.alipay.mychain.sdk.api.Mychain;
import com.alipay.mychain.sdk.api.request.MychainParams;
import com.alipay.mychain.sdk.api.request.account.CreateAccountRequest;
import com.alipay.mychain.sdk.api.request.contract.CallContractRequest;
import com.alipay.mychain.sdk.api.request.contract.DeployContractRequest;
import com.alipay.mychain.sdk.api.result.MychainBaseResult;
import com.alipay.mychain.sdk.config.ISslOption;
import com.alipay.mychain.sdk.config.MychainEnv;
import com.alipay.mychain.sdk.config.SslBytesOption;
import com.alipay.mychain.sdk.domain.account.Account;
import com.alipay.mychain.sdk.domain.account.AuthMap;
import com.alipay.mychain.sdk.domain.account.Identity;
import com.alipay.mychain.sdk.domain.account.ObjectStatus;
import com.alipay.mychain.sdk.domain.common.BaseFixedSizeUnsignedInteger;
import com.alipay.mychain.sdk.domain.common.PublicKey;
import com.alipay.mychain.sdk.domain.status.VMTypeEnum;
import com.alipay.mychain.sdk.exceptions.errorcode.MychainErrorCodeEnum;
import com.alipay.mychain.sdk.exceptions.errorcode.MychainSdkErrorCodeEnum;
import com.alipay.mychain.sdk.message.response.ReplyTransactionReceipt;
import com.alipay.mychain.sdk.message.response.Response;
import com.alipay.mychain.sdk.network.ClientTypeEnum;
import com.alipay.mychain.sdk.tools.codec.CodecTypeEnum;
import com.alipay.mychain.sdk.tools.codec.contract.ContractParameters;
import com.alipay.mychain.sdk.tools.codec.contract.ContractReturnValues;
import com.alipay.mychain.sdk.tools.crypto.KeyLoder;
import com.alipay.mychain.sdk.tools.hash.HashTypeEnum;
import com.alipay.mychain.sdk.tools.keypair.RSAKeypair;
import com.alipay.mychain.sdk.tools.log.LoggerFactory;
import com.alipay.mychain.sdk.tools.sign.AbstractKeyPair;
import com.alipay.mychain.sdk.tools.sign.KeyPairFactory;
import com.alipay.mychain.sdk.tools.sign.SignTypeEnum;
import com.alipay.mychain.sdk.tools.utils.ByteUtils;
import com.alipay.mychain.sdk.tools.utils.Utils;
import org.slf4j.Logger;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import static com.alipay.mychain.sdk.exceptions.errorcode.MychainSdkErrorCodeEnum.SDK_INTERNAL_ERROR;


public class DemoSample {
    /**
     * contract code
     */
    private static String contractCodeString
            =
            "6080604052633b9aca00600055600060015534801561001d57600080fd5b5033600281905550610492806100346000396000f3006080604"
                    +
                    "05260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063"
                    +
                    "af7c102c1461005c578063b2628df81461009d578063d4486019146100ec575b600080fd5b34801561006857600080fd5b5061008"
                    +
                    "76004803603810190808035906020019092919050505061013b565b6040518082815260200191505060405180910390f35b348015"
                    +
                    "6100a957600080fd5b506100d26004803603810190808035906020019092919080359060200190929190505050610158565b60405"
                    +
                    "1808215151515815260200191505060405180910390f35b3480156100f857600080fd5b5061012160048036038101908080359060"
                    +
                    "200190929190803590602001909291905050506102d8565b604051808215151515815260200191505060405180910390f35b60006"
                    +
                    "0036000838152602001908152602001600020549050919050565b6000600254331415156101d3576040517f08c379a00000000000"
                    +
                    "000000000000000000000000000000000000000000000081526004018080602001828103825260118152602001807f5065726d697"
                    +
                    "373696f6e2064656e69656400000000000000000000000000000081525060200191505060405180910390fd5b6000548260015401"
                    +
                    "131580156101ee57506001548260015401135b80156101fa5750600082135b151561026e576040517f08c379a0000000000000000"
                    +
                    "00000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f496e76616c696420"
                    +
                    "76616c75652100000000000000000000000000000000000081525060200191505060405180910390fd5b816003600085815260200"
                    +
                    "190815260200160002060008282540192505081905550816001600082825401925050819055508183337f31a52246bf8c995cecfd"
                    +
                    "d5404cf290ae6c2f4e174e888e4de4fd208137ec274d60405160405180910390a46001905092915050565b6000816003600033815"
                    +
                    "26020019081526020016000205412151515610365576040517f08c379a00000000000000000000000000000000000000000000000"
                    +
                    "000000000081526004018080602001828103825260138152602001807f62616c616e6365206e6f7420656e6f75676821000000000"
                    +
                    "0000000000000000081525060200191505060405180910390fd5b60008213801561037757506000548213155b15156103eb576040"
                    +
                    "517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e815"
                    +
                    "2602001807f496e76616c69642076616c756521000000000000000000000000000000000000815250602001915050604051809103"
                    +
                    "90fd5b816003600033815260200190815260200160002060008282540392505081905550816003600085815260200190815260200"
                    +
                    "1600020600082825401925050819055508183337f97c0c2106db19ca3c64afdc86820cd157d60361f777bf0e5323254d6c9689550"
                    +
                    "60405160405180910390a460009050929150505600a165627a7a72305820371af9e83b0e49ca71634c470c75e504d08db9abbaf39"
                    + "92f30434f8d7a7994d40029";
    private static byte[] contractCode = ByteUtils.hexStringToBytes(contractCodeString);
    /**
     * contract id
     */
    private static String testContractId = "CreditManager" + System.currentTimeMillis();
    /**
     * accounts
     */
    private static Identity userAccount;
    private static PrivateKey userPrivateKey;

    private static Account testAccount1;
    private static Account testAccount2;
    /**
     * key pair for testKeyPair1
     */
    private static AbstractKeyPair testKeyPair1;
    /**
     * key pair for testKeyPair2
     */
    private static AbstractKeyPair testKeyPair2;
    /**
     * sdk client
     */
    private static Mychain sdk;
    /**
     * client key password
     */
    private static String keyPassword = "1234abAB*";  //根据实际情况更新，申请证书时候指定的SSL密码
    /**
     * user password
     */
    private static String userPassword = "1234abAB*"; //根据实际情况更新。申请证书时，创建账户的密码
    /**
     * host ip
     */

    private static String host = "47.102.110.103"; //根据实际情况更新，在BaaS平台，通过查看目标合约链"详情"，在"区块浏览器"中查看"节点详情"可获取链节点的 IP地址 和 端口号。
    /**
     * server port
     */
    private static int port = 18130;               //根据实际情况更新
    /**
     * trustCa password.
     */
    private static String trustStorePassword = "mychain";
    /**
     * mychain environment
     */
    private static MychainEnv env;
    /**
     * mychain is gm Chain
     */
    private static boolean isSMChain = false;
    /**
     * mychain is tee Chain
     */
    private static boolean isTeeChain = false;
    /**
     * tee chain publicKeys
     */
    private static List<byte[]> publicKeys = new ArrayList<byte[]>();
    /**
     * tee chain secretKey
     */
    private static byte[] secretKey = null;
    /**
     * key list
     */
    private static ArrayList<PrivateKey> userPrivateKeyArrayList = new ArrayList<PrivateKey>();
    private static ArrayList<PrivateKey> test1PrivateKeyArrayList = new ArrayList<PrivateKey>();
    private static ArrayList<PrivateKey> test2PrivateKeyArrayList = new ArrayList<PrivateKey>();

    private static void initLogger() {
        Logger logger = org.slf4j.LoggerFactory.getLogger(DemoSample.class);
        LoggerFactory.setInstance(logger);
    }

    private static void initAccount() throws Exception{
        long startIndex = System.currentTimeMillis();
        String testAccount1Identity = "account_" + startIndex;
        String testAccount2Identity = "account_" + (startIndex + 1);

        SignTypeEnum signType = SignTypeEnum.ECDSA;
        if (isSMChain) {
            signType = SignTypeEnum.SM3withSM2;
        }
        // generate key pair
        try {
            testKeyPair1 = KeyPairFactory.getMyKeyPair(signType);
        } catch (Exception e) {
            e.printStackTrace();
            exit("initAccount", "create testKeyPair1 error");
        }

        try {
            testKeyPair2 = KeyPairFactory.getMyKeyPair(signType);
        } catch (Exception e) {
            e.printStackTrace();
            exit("initAccount", "create testKeyPair2 error");
        }

        // build account
        testAccount1 = new Account();
        testAccount1.setIdentity(Utils.getIdentityByName(testAccount1Identity, env));
        testAccount1.setBalance(0);
        testAccount1.setStatus(ObjectStatus.NORMAL);
        testAccount1.setAuthMap(AuthMap.buildEmpty().updateAuth(testKeyPair1.getHexStringPublicKey(), 100));
        testAccount1.setRecoverKey(new PublicKey(testKeyPair1.getHexStringPublicKey()));

        testAccount2 = new Account();
        testAccount2.setIdentity(Utils.getIdentityByName(testAccount2Identity, env));
        testAccount2.setBalance(0);
        testAccount2.setStatus(ObjectStatus.NORMAL);
        testAccount2.setAuthMap(AuthMap.buildEmpty().updateAuth(testKeyPair2.getHexStringPublicKey(), 100));
        testAccount2.setRecoverKey(new PublicKey(testKeyPair2.getHexStringPublicKey()));
    }

    private static void exit(String tag, String msg) {
        exit(String.format("%s error : %s ", tag, msg));
    }

    private static void exit(String msg) {
        System.out.println(msg);
        System.exit(0);
    }

    private static String getErrorMsg(int errorCode) {
        int minMychainSdkErrorCode = Integer.valueOf(SDK_INTERNAL_ERROR.getErrorCode());
        if (errorCode < minMychainSdkErrorCode) {
            return MychainErrorCodeEnum.valueOf(errorCode).getErrorDesc();
        } else {
            return MychainSdkErrorCodeEnum.valueOf(errorCode).getErrorDesc();
        }
    }

    private static void initMychainEnv() {
        env = buildMychainEnv("test_sdk");
    }

    private static MychainEnv buildMychainEnv(String identity) {
        InetSocketAddress inetSocketAddress = InetSocketAddress.createUnresolved(host, port);
        String keyFilePath = "client.key";
        String certFilePath = "client.crt";
        String trustStoreFilePath = "trustCa";

        // any user key for sign message
        String userPrivateKeyFile = "user.key";
        userAccount = Utils.getIdentityByName("0505"); //根据实际情况更新'gushui03'为'user.key'对应的账户名(BaaS申请证书时创建的账户名)
        userPrivateKey = KeyLoder.getPrivateKeyFromPKCS8(DemoSample.class.getClassLoader().getResourceAsStream(userPrivateKeyFile),userPassword);

        // build ssl option
        ISslOption sslOption = new SslBytesOption.Builder()
                .keyBytes(Utils.readFileToByteArray(DemoSample.class.getClassLoader().getResource(keyFilePath).getPath()))
                .certBytes(Utils.readFileToByteArray(DemoSample.class.getClassLoader().getResource(certFilePath).getPath()))
                .keyPassword(keyPassword)
                .trustStorePassword(trustStorePassword)
                .trustStoreBytes(
                        Utils.readFileToByteArray(DemoSample.class.getClassLoader().getResource(trustStoreFilePath).getPath()))
                .build();

        // multi nodes configuration
        List<SocketAddress> backupNodes = new ArrayList<SocketAddress>();
//        backupNodes.add(InetSocketAddress.createUnresolved("47.100.27.162", 18130));
//        backupNodes.add(InetSocketAddress.createUnresolved("106.14.218.105", 18130));
//        backupNodes.add(InetSocketAddress.createUnresolved("47.100.115.103", 18130));

        HashTypeEnum hashType = HashTypeEnum.SHA256;
        SignTypeEnum signType = SignTypeEnum.ECDSA;
        if(isSMChain) {
            hashType = HashTypeEnum.SM3;
            signType = SignTypeEnum.SM3withSM2;
        }

        return MychainEnv.build(identity, ClientTypeEnum.TLS, hashType,
                signType, CodecTypeEnum.RLP, inetSocketAddress, sslOption, backupNodes);
    }

    private static void initPrivateKeyList() {
        PrivateKey test1PrivateKey = null;
        try {
            test1PrivateKey = testKeyPair1.getEcPrivateKey();
        } catch (Exception e) {
            e.printStackTrace();
            exit("initPrivateKeyList", "create test1PrivateKey failed");
        }

        PrivateKey test2PrivateKey = null;
        try {
            test2PrivateKey = testKeyPair2.getEcPrivateKey();
        } catch (Exception e) {
            e.printStackTrace();
            exit("initPrivateKeyList", "create test2PrivateKey failed");
        }

        // add all private keys into list
        userPrivateKeyArrayList.add(userPrivateKey);
        test1PrivateKeyArrayList.add(test1PrivateKey);
        test2PrivateKeyArrayList.add(test2PrivateKey);
    }

    private static void createAccount() {
        MychainParams params = new MychainParams.Builder()
                .gas(BigInteger.valueOf(4000000))
                .privateKeyList(userPrivateKeyArrayList)
                .build();

        // build CreateAccountRequest, user.key account creates testAccount1
        CreateAccountRequest request = CreateAccountRequest.build(userAccount,
                testAccount1, params, System.currentTimeMillis(), 0,
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE));

        // create testAccount1
        MychainBaseResult<ReplyTransactionReceipt> createAccountResult = sdk.getAccountService().createAccount(request);
        if (!createAccountResult.isSuccess()) {
            exit("createAccount", getErrorMsg((int)createAccountResult.getData().getTransactionReceipt().getResult()));
        } else {
            System.out.println("create testAccount1 success.");
        }

        // build testAccount2 request, user.key account creates testAccount2
        CreateAccountRequest createAccount2Request = CreateAccountRequest.build(userAccount,
                testAccount2, params, System.currentTimeMillis(), 0,
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE));

        // create testAccount2
        MychainBaseResult<ReplyTransactionReceipt> createAccountResult2 = sdk.getAccountService().createAccount(
                createAccount2Request);
        if (!createAccountResult2.isSuccess()) {
            exit("createAccount", getErrorMsg((int)createAccountResult2.getData().getTransactionReceipt().getResult()));
        } else {
            System.out.println("create testAccount2 success.");
        }

    }

    private static void deployContract() {
        if (isTeeChain) {
            byte[] publicKeyDer = KeyLoder.getPublicKeyFromPKCS8(DemoSample.class.getClassLoader().getResourceAsStream("tee_rsa_public_key.pem")).getEncoded(); //tee_rsa_public_key.pem 从BaaS下载获取
            publicKeys.add(publicKeyDer);
            secretKey = ByteUtils.hexStringToBytes("123456");
        }

        MychainParams params = getMychainParams(test1PrivateKeyArrayList);
        ContractParameters contractParameters = new ContractParameters();

        // build DeployContractRequest
        DeployContractRequest request = DeployContractRequest.build(testAccount1.getIdentity(),
                Utils.getIdentityByName(testContractId, env), contractCode, VMTypeEnum.EVM,
                contractParameters, BigInteger.ZERO, params, 0, 0,
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE));

        // deploy contract
        MychainBaseResult<ReplyTransactionReceipt> deployContractResult = sdk.getContractService().deployContract(request);
        if (!deployContractResult.isSuccess() || deployContractResult.getData().getTransactionReceipt().getResult() != 0) {
            exit("deployContract",
                    getErrorMsg((int)deployContractResult.getData().getTransactionReceipt().getResult()));
        } else {
            System.out.println("deploy contract success.");
        }
    }

    private static void issue() {
        MychainParams params = getMychainParams(test1PrivateKeyArrayList);

        // contract parameters
        ContractParameters parameters = new ContractParameters("Issue(identity,int256)");
        parameters.addIdentity(testAccount2.getIdentity());
        parameters.addUint(BigInteger.valueOf(100));

        // build CallContractRequest
        CallContractRequest request = CallContractRequest.build(testAccount1.getIdentity(),
                Utils.getIdentityByName(testContractId, env), parameters, BigInteger.ZERO, params, 0, 0,
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE));

        // call contract
        MychainBaseResult<ReplyTransactionReceipt> issueResult = sdk.getContractService().callContract(request);
        if (!issueResult.isSuccess() || issueResult.getData().getTransactionReceipt().getResult() != 0 ) {
            exit("issue", getErrorMsg((int)issueResult.getData().getTransactionReceipt().getResult()));
        } else {
            System.out.println("issue success.");
        }
    }

    private static void transfer() {
        // common parameters
        MychainParams params = getMychainParams(test2PrivateKeyArrayList);

        // contract parameters
        ContractParameters parameters = new ContractParameters("Transfer(identity,int256)");
        parameters.addIdentity(testAccount1.getIdentity());
        parameters.addUint(BigInteger.valueOf(50));

        CallContractRequest request = CallContractRequest.build(testAccount2.getIdentity(),
                Utils.getIdentityByName(testContractId, env), parameters, BigInteger.ZERO, params, 0, 0,
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE));

        // call contract
        MychainBaseResult<ReplyTransactionReceipt> callContractResult = sdk.getContractService().callContract(request);
        if (!callContractResult.isSuccess() || callContractResult.getData().getTransactionReceipt().getResult() != 0) {
            exit("transfer", getErrorMsg((int)callContractResult.getData().getTransactionReceipt().getResult()));
        } else {
            System.out.println("transfer success.");
        }
    }

    private static BigInteger query(ArrayList<PrivateKey> privateKeyArrayList, Account account) {
        MychainParams params = getMychainParams(privateKeyArrayList);

        // contract parameters
        ContractParameters parameters = new ContractParameters("Query(identity)");
        parameters.addIdentity(account.getIdentity());

        // build call contract request
        CallContractRequest request = CallContractRequest.build(account.getIdentity(),
                Utils.getIdentityByName(testContractId, env), parameters, BigInteger.ZERO, params, 0, 0,
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE));

        // call contract
        MychainBaseResult<ReplyTransactionReceipt> issueResult = sdk.getContractService().callContract(request);
        if (!issueResult.isSuccess() || issueResult.getData().getTransactionReceipt().getResult() != 0) {
            exit("query", getErrorMsg((int)issueResult.getData().getTransactionReceipt().getResult()));
        }

        // decode return values
        ContractReturnValues contractReturnValues = null;
        if (isTeeChain) {
            byte[] output = RSAKeypair.decrypt(secretKey,issueResult.getData().getTransactionReceipt().getOutput(), issueResult.getTxHash());

            // decode return values
            contractReturnValues = new ContractReturnValues(
                    ByteUtils.toHexString(output));
        } else {
            contractReturnValues = new ContractReturnValues(
                    ByteUtils.toHexString(issueResult.getData().getTransactionReceipt().getOutput()));
        }
        return contractReturnValues.getUint();
    }

    private static MychainParams getMychainParams(ArrayList<PrivateKey> privateKeyArrayList){
        MychainParams params = null;
        if (isTeeChain) {
            params = new MychainParams.Builder()
                    .gas(BigInteger.valueOf(4000000))
                    .privateKeyList(privateKeyArrayList)
                    .setEncryptedTx(true)
                    .setAesgcm(secretKey)
                    .setRsaPublicKeys(publicKeys)
                    .build();
        } else {
            params = new MychainParams.Builder()
                    .gas(BigInteger.valueOf(4000000))
                    .privateKeyList(privateKeyArrayList)
                    .build();
        }

        return params;
    }

    private static void expect(BigInteger balance, BigInteger expectBalance) {
        if (balance.compareTo(expectBalance) != 0) {
            exit("expect", "the account value is not expected.");
        } else {
            System.out.println("check account balance success.");
        }
    }

    private static void initSdk() {
        sdk = new Mychain();
        MychainBaseResult<Response> initResult = sdk.init(env);
        if (!initResult.isSuccess()) {
            exit("initSdk", "sdk init failed.");
        }
    }

    public static void main(String[] args) throws Exception{

        //step 1: init logger.
        initLogger();

        //step 2:init mychain env.
        initMychainEnv();

        // step 3: init sdk client
        initSdk();

        //step 4: init account that will be created.
        initAccount();

        //step 5: init private key list which will be used during transaction.
        initPrivateKeyList();

        //step 6: execute create two accounts.
        createAccount();

        //step 7 : deploy a contract using testAccount1.
        deployContract();

        //step 8:issue 100 assets to testAccount2.
        issue();

        //step 9 : transfer 50 assets from testAccount2 to testAccount1
        transfer();

        //step 10 : query testAccount2 whose balance should be 50.
        BigInteger balance = query(test2PrivateKeyArrayList, testAccount2);

        //step 11 : compare to expect balance.
        expect(balance, BigInteger.valueOf(50));

        //step 12 : sdk shut down
        sdk.shutDown();
    }
}
