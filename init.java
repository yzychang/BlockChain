package com.example.demo;

import com.alipay.mychain.sdk.api.Mychain;
import com.alipay.mychain.sdk.api.request.MychainParams;
import com.alipay.mychain.sdk.api.request.account.CreateAccountRequest;
import com.alipay.mychain.sdk.api.request.contract.CallContractRequest;
import com.alipay.mychain.sdk.api.request.contract.DeployContractRequest;
import com.alipay.mychain.sdk.api.request.contract.UpdateContractRequest;
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
import com.alipay.mychain.sdk.message.response.ReplyTransaction;
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


public class init {
    /**
     * contract code
     */
    private static String contractCodeString
            ="0x60806040523480156200001157600080fd5b50600080600091505b600a8210156200008c5760006040805190810160405280848152602001600081525090806001815401808255809150509060018203906000526020600020906002020160009091929091909150600082015181600001556020820151816001015550505081806001019250506200001a565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600080815481101515620000bd57fe5b9060005260206000209060020201600101819055506000806001815481101515620000e457fe5b9060005260206000209060020201600101819055600060028154811015156200010957fe5b9060005260206000209060020201600101819055600060038154811015156200012e57fe5b9060005260206000209060020201600101819055506001600060058154811015156200015657fe5b9060005260206000209060020201600101819055600060048154811015156200017b57fe5b906000526020600020906002020160010181905550600260006007815481101515620001a357fe5b906000526020600020906002020160010181905560006006815481101515620001c857fe5b906000526020600020906002020160010181905550600360006009815481101515620001f057fe5b9060005260206000209060020201600101819055600060088154811015156200021557fe5b906000526020600020906002020160010181905550600090505b600a811015620002a15760016040805190810160405280838152602001600081525090806001815401808255809150509060018203906000526020600020906002020160009091929091909150600082015181600001556020820151816001015550505080806001019150506200022f565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60016000815481101515620002d357fe5b906000526020600020906002020160010181905550600060016003815481101515620002fb57fe5b9060005260206000209060020201600101819055600160028154811015156200032057fe5b90600052602060002090600202016001018190556001808154811015156200034457fe5b90600052602060002090600202016001018190555060018060058154811015156200036b57fe5b9060005260206000209060020201600101819055600160048154811015156200039057fe5b906000526020600020906002020160010181905550600260016007815481101515620003b857fe5b906000526020600020906002020160010181905560016006815481101515620003dd57fe5b9060005260206000209060020201600101819055506003600160098154811015156200040557fe5b9060005260206000209060020201600101819055600160088154811015156200042a57fe5b90600052602060002090600202016001018190555050506116f780620004516000396000f3006080604052600436106100d0576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806313073320146100d557806328a08c181461011a5780633c9d9d8c1461015b5780633ef61573146101a357806341161b10146101ee57806342ecf8bb1461023d5780636d669d2b1461028857806377f52f7b146102d3578063a750e91814610314578063b9a5d7a914610363578063ca568a43146103ae578063cfbc4a82146103f3578063e191a1631461043e578063e76a5f0614610486575b600080fd5b3480156100e157600080fd5b50610100600480360381019080803590602001909291905050506104d5565b604051808215151515815260200191505060405180910390f35b34801561012657600080fd5b506101456004803603810190808035906020019092919050505061081a565b6040518082815260200191505060405180910390f35b34801561016757600080fd5b50610186600480360381019080803590602001909291905050506109fc565b604051808381526020018281526020019250505060405180910390f35b3480156101af57600080fd5b506101d86004803603810190808035906020019092919080359060200190929190505050610a2f565b6040518082815260200191505060405180910390f35b3480156101fa57600080fd5b506102236004803603810190808035906020019092919080359060200190929190505050610b4d565b604051808215151515815260200191505060405180910390f35b34801561024957600080fd5b506102726004803603810190808035906020019092919080359060200190929190505050610b8a565b6040518082815260200191505060405180910390f35b34801561029457600080fd5b506102bd6004803603810190808035906020019092919080359060200190929190505050610bba565b6040518082815260200191505060405180910390f35b3480156102df57600080fd5b506102fe60048036038101908080359060200190929190505050610cd8565b6040518082815260200191505060405180910390f35b34801561032057600080fd5b506103496004803603810190808035906020019092919080359060200190929190505050610e04565b604051808215151515815260200191505060405180910390f35b34801561036f57600080fd5b506103986004803603810190808035906020019092919080359060200190929190505050610f7c565b6040518082815260200191505060405180910390f35b3480156103ba57600080fd5b506103d96004803603810190808035906020019092919050505061109d565b604051808215151515815260200191505060405180910390f35b3480156103ff57600080fd5b5061042860048036038101908080359060200190929190803590602001909291905050506112e5565b6040518082815260200191505060405180910390f35b34801561044a57600080fd5b5061046960048036038101908080359060200190929190505050611406565b604051808381526020018281526020019250505060405180910390f35b34801561049257600080fd5b506104bb6004803603810190808035906020019092919080359060200190929190505050611439565b604051808215151515815260200191505060405180910390f35b6000806000806000806000809450600093505b6001805490508410156106385760018481548110151561050457fe5b90600052602060002090600202016000015488141561062b5760018481548110151561052c57fe5b906000526020600020906002020160010154955060018080805490500381548110151561055557fe5b90600052602060002090600202016001015460018581548110151561057657fe5b9060005260206000209060020201600101819055506001808080549050038154811015156105a057fe5b9060005260206000209060020201600001546001858154811015156105c157fe5b9060005260206000209060020201600001819055506001808080549050038154811015156105eb57fe5b906000526020600020906002020160008082016000905560018201600090555050600180548091906001900361062191906115b8565b5060019450610638565b83806001019450506104e8565b600092505b6001805490508310156106a9578760018481548110151561065a57fe5b906000526020600020906002020160010154141561069c578560018481548110151561068257fe5b906000526020600020906002020160010181905550600194505b828060010193505061063d565b600091505b60008054905082101561080b57600090505b60026000838152602001908152602001600020805490508110156107fe578760026000848152602001908152602001600020828154811015156106ff57fe5b906000526020600020015414156107f15760026000838152602001908152602001600020600160026000858152602001908152602001600020805490500381548110151561074957fe5b9060005260206000200154600260008481526020019081526020016000208281548110151561077457fe5b90600052602060002001819055506002600083815260200190815260200160002060016002600085815260200190815260200160002080549050038154811015156107bb57fe5b9060005260206000200160009055600260008381526020019081526020016000208054809190600190036107ef91906115ea565b505b80806001019150506106c0565b81806001019250506106ae565b60019650505050505050919050565b6000806000806000807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff945060009350600092505b600080549050831015610895578660008481548110151561086c57fe5b9060005260206000209060020201600001541415610888578294505b828060010193505061084f565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8514156108c5578395506109f2565b600092505b600260008881526020019081526020016000208054905083101561092757600260008881526020019081526020016000208381548110151561090857fe5b906000526020600020015460020a8417935082806001019350506108ca565b600192505b60008581548110151561093b57fe5b90600052602060002090600202016001015491507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82141561097c576109ee565b600090505b60026000838152602001908152602001600020805490508110156109de5760026000838152602001908152602001600020818154811015156109bf57fe5b906000526020600020015460020a841793508080600101915050610981565b819450828060010193505061092c565b8395505b5050505050919050565b600181815481101515610a0b57fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000806000806000925060009150600090505b600180549050811015610abb57600181815481101515610a5e57fe5b906000526020600020906002020160000154851480610a9c57507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff85145b15610aaa5760009250610abb565b600292508080600101915050610a42565b600090505b600180549050811015610b1257600181815481101515610adc57fe5b906000526020600020906002020160000154861415610b015780915060009250610b12565b600192508080600101915050610ac0565b6000831415610b415784600183815481101515610b2b57fe5b9060005260206000209060020201600101819055505b82935050505092915050565b6000806000610b5b8561081a565b9150610b6684610cd8565b90506000818316141515610b7d5760019250610b82565b600092505b505092915050565b600260205281600052604060002081815481101515610ba557fe5b90600052602060002001600091509150505481565b6000806000806000925060009150600090505b600080549050811015610c4657600081815481101515610be957fe5b906000526020600020906002020160000154851480610c2757507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff85145b15610c355760009250610c46565b600292508080600101915050610bcd565b600090505b600080549050811015610c9d57600081815481101515610c6757fe5b906000526020600020906002020160000154861415610c8c5780915060009250610c9d565b600192508080600101915050610c4b565b6000831415610ccc5784600083815481101515610cb657fe5b9060005260206000209060020201600101819055505b82935050505092915050565b60008060008060007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff935060009250600091505b600180549050821015610d525785600183815481101515610d2957fe5b9060005260206000209060020201600001541415610d45578193505b8180600101925050610d0c565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff841415610d8257829450610dfb565b8560020a83179250600191505b600184815481101515610d9e57fe5b90600052602060002090600202016001015490507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff811415610ddf57610df7565b8060020a831792508093508180600101925050610d8f565b8294505b50505050919050565b6000806000806000809350600092505b600180549050831015610e635785600184815481101515610e3157fe5b9060005260206000209060020201600001541415610e525760009350610e63565b600193508280600101935050610e14565b600091505b600080549050821015610eb75786600083815481101515610e8557fe5b9060005260206000209060020201600001541415610ea65760009350610eb7565b600293508180600101925050610e68565b600090505b6002600088815260200190815260200160002080549050811015610f2657856002600089815260200190815260200160002082815481101515610efb57fe5b90600052602060002001541415610f19576003935060019450610f72565b8080600101915050610ebc565b6000841415610f6d57600260008881526020019081526020016000208690806001815401808255809150509060018203906000526020600020016000909192909190915055505b600194505b5050505092915050565b6000806000809150600090505b60018054905081101561102f57600181815481101515610fa557fe5b906000526020600020906002020160000154851415610fc357600191505b600181815481101515610fd257fe5b90600052602060002090600202016000015484148061101057507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff84145b1561101e576000915061102f565b600291508080600101915050610f89565b60008214156110925760016040805190810160405280878152602001868152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050505b819250505092915050565b60008060008060008060009450600092505b600080549050831015611205576000838154811015156110cb57fe5b9060005260206000209060020201600001548714156111f8576000838154811015156110f357fe5b9060005260206000209060020201600101549350600060016000805490500381548110151561111e57fe5b90600052602060002090600202016001015460008481548110151561113f57fe5b906000526020600020906002020160010181905550600060016000805490500381548110151561116b57fe5b90600052602060002090600202016000015460008481548110151561118c57fe5b90600052602060002090600202016000018190555060006001600080549050038154811015156111b857fe5b90600052602060002090600202016000808201600090556001820160009055505060008054809190600190036111ee9190611616565b5060019450611205565b82806001019350506110af565b600091505b600080549050821015611276578660008381548110151561122757fe5b9060005260206000209060020201600101541415611269578360008381548110151561124f57fe5b906000526020600020906002020160010181905550600194505b818060010192505061120a565b600090505b60026000888152602001908152602001600020805490508110156112d85760026000888152602001908152602001600020818154811015156112b957fe5b906000526020600020016000905560019450808060010191505061127b565b8495505050505050919050565b6000806000809150600090505b6000805490508110156113985760008181548110151561130e57fe5b90600052602060002090600202016000015485141561132c57600191505b60008181548110151561133b57fe5b90600052602060002090600202016000015484148061137957507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff84145b156113875760009150611398565b6002915080806001019150506112f2565b60008214156113fb5760006040805190810160405280878152602001868152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050505b819250505092915050565b60008181548110151561141557fe5b90600052602060002090600202016000915090508060000154908060010154905082565b600080600060026000868152602001908152602001600020805490501415156115b057600090505b60026000858152602001908152602001600020805490508110156115a7578260026000868152602001908152602001600020828154811015156114a057fe5b9060005260206000200154141561159a576002600085815260200190815260200160002060016002600087815260200190815260200160002080549050038154811015156114ea57fe5b9060005260206000200154600260008681526020019081526020016000208281548110151561151557fe5b906000526020600020018190555060026000858152602001908152602001600020600160026000878152602001908152602001600020805490500381548110151561155c57fe5b90600052602060002001600090556002600085815260200190815260200160002080548091906001900361159091906115ea565b50600191506115b1565b8080600101915050611461565b600091506115b1565b5b5092915050565b8154818355818111156115e5576002028160020283600052602060002091820191016115e49190611648565b5b505050565b815481835581811115611611578183600052602060002091820191016116109190611677565b5b505050565b81548183558181111561164357600202816002028360005260206000209182019101611642919061169c565b5b505050565b61167491905b808211156116705760008082016000905560018201600090555060020161164e565b5090565b90565b61169991905b8082111561169557600081600090555060010161167d565b5090565b90565b6116c891905b808211156116c4576000808201600090556001820160009055506002016116a2565b5090565b905600a165627a7a723058201f7ba0d057cffc255085f56655333d5b9064555ee59b5b64b8077ac2c98d29ff0029";
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
    public static Mychain sdk;
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

    public static void initLogger() {
        Logger logger = org.slf4j.LoggerFactory.getLogger(init.class);
        LoggerFactory.setInstance(logger);
    }

    public static void initAccount() throws Exception{
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

    public static void initMychainEnv() {
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
        userPrivateKey = KeyLoder.getPrivateKeyFromPKCS8(init.class.getClassLoader().getResourceAsStream(userPrivateKeyFile),userPassword);

        // build ssl option
        ISslOption sslOption = new SslBytesOption.Builder()
                .keyBytes(Utils.readFileToByteArray(init.class.getClassLoader().getResource(keyFilePath).getPath()))
                .certBytes(Utils.readFileToByteArray(init.class.getClassLoader().getResource(certFilePath).getPath()))
                .keyPassword(keyPassword)
                .trustStorePassword(trustStorePassword)
                .trustStoreBytes(
                        Utils.readFileToByteArray(init.class.getClassLoader().getResource(trustStoreFilePath).getPath()))
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

    public static void initPrivateKeyList() {
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

    public static void createAccount() {
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

    public static void initSdk() {
        sdk = new Mychain();
        MychainBaseResult<Response> initResult = sdk.init(env);
        if (!initResult.isSuccess()) {
            exit("initSdk", "sdk init failed.");
        }
    }

    public static void init(){
        //step 1: init logger.
        init.initLogger();

        //step 2:init mychain env.
        init.initMychainEnv();

        // step 3: init sdk client
        init.initSdk();

        //step 4: init account that will be created.
        // 由于init.initAccount()函数声明中表明有可能有异常，故此处需要在调用该函数时放到“try”语句里捕获异常，并用“catch”语句处理异常
        try{
            init.initAccount();
        }catch(Exception e){
            System.out.print("Init account failed!");
        }

        //step 5: init private key list which will be used during transaction.
        init.initPrivateKeyList();

        //step 6: execute create two accounts.
        init.createAccount();
    }

    public static byte[] stringToBytes(String str){
        byte[] result = new byte[32];
        byte[] stringToByte = str.getBytes();
        int len = stringToByte.length;
        for(int i=0; i<len; i++){
            //System.out.print(i);
            //System.out.print("  ");
            result[i] = stringToByte[i];
        }
        // 将数组byte[32]转为bytes32类型
        //Bytes32 resultBytes32 = new Bytes32(result);
        return result;
    }

    public static void deployContract() {
        if (isTeeChain) {
            byte[] publicKeyDer = KeyLoder.getPublicKeyFromPKCS8(init.class.getClassLoader().getResourceAsStream("tee_rsa_public_key.pem")).getEncoded(); //tee_rsa_public_key.pem 从BaaS下载获取
            publicKeys.add(publicKeyDer);
            secretKey = ByteUtils.hexStringToBytes("123456");
        }

        MychainParams params = getMychainParams(test1PrivateKeyArrayList);
        ContractParameters contractParameters = new ContractParameters();
       // contractParameters.addString("a");

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

    public static String AddMap(int addrole, int addpurpose) {
      //public static String AddMap(String user, String role, String purpose) {
        // common parameters
        MychainParams params1 = getMychainParams(test2PrivateKeyArrayList);


          // contract parameters，指定要调用的合约接口以及该接口需要的参数
//        ContractParameters parameters1 = new ContractParameters("verify(bytes32,bytes32,bytes32)"); // 指定要调用的合约接口
//        parameters1.addBytes32(stringToBytes(user));
//        parameters1.addBytes32(stringToBytes(role));
//        parameters1.addBytes32(stringToBytes(purpose));

        ContractParameters parameters1 = new ContractParameters("AddOneMap(uint256,uint256)"); // 指定要调用的合约接口
        String c=String.valueOf(addrole);
        System.out.println(c.getClass().getName());
        String d=String.valueOf(addpurpose);
        System.out.println(d.getClass().getName());
        parameters1.addUint(new BigInteger(c));
        parameters1.addUint(new BigInteger(d));

        // contract request
        CallContractRequest request1 = CallContractRequest.build(testAccount2.getIdentity(), // 调用合约的账户ID
                Utils.getIdentityByName(testContractId, env), // 被调用的合约ID
                parameters1, // 被调用的合约接口及其需要的参数
                BigInteger.ZERO, // 值（是不是交易的金额？）
                params1, // 链的参数
                0, // 时间戳（不造干啥）
                0, // 时长（不造干啥）
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE)); // 不造干啥的



        MychainBaseResult<ReplyTransactionReceipt> callContractResult = sdk.getContractService().callContract(request1);

//        MychainBaseResult<Response> callContractResult= sdk.getContractService().asyncCallContract(
//                CallContractRequest.build(
//                        testAccount2.getIdentity(),
//                        Utils.getIdentityByName(testContractId),
//                        parameters1,
//                        BigInteger.ZERO,
//                        params1
//                ),
//                (txHash, response) -> {
//                    System.out.println("async call contract, txHash:"+txHash+", result: "+ response.getErrorCode());
//                }
//        );

        System.out.println(callContractResult.isSuccess());
        System.out.println(callContractResult.getData().getTransactionReceipt().getResult());
        if (!callContractResult.isSuccess() || callContractResult.getData().getTransactionReceipt().getResult() != 0) {
            exit("AddOneMap", getErrorMsg((int)callContractResult.getData().getTransactionReceipt().getResult()));
        } else {
           //System.out.println("verify " + user + " for purpose " + purpose + " success!");
           System.out.println("AddOneMap " +"addrole:" + String.valueOf(addrole)+"  addpurpose:" +String.valueOf(addpurpose));
        }

        String txHash = callContractResult.getTxHash();
        System.out.println(txHash);
        return txHash;
        //TransactionReceipt a = callContractResult.getData().getTransactionReceipt();
        //byte[] b = a.getOutput();
        //List<LogEntry> c = a.getLogs();
    }





    public static String verifyAccess(int role, int purpose) {
        // common parameters
        MychainParams params2 = getMychainParams(test2PrivateKeyArrayList);

        // contract parameters，指定要调用的合约接口以及该接口需要的参数
        ContractParameters parameters2 = new ContractParameters("verify(uint256,uint256)"); // 指定要调用的合约接口
        String e=String.valueOf(role);
        System.out.println(e.getClass().getName());
        String f=String.valueOf(purpose);
        System.out.println(f.getClass().getName());
        parameters2.addUint(new BigInteger(e));
        parameters2.addUint(new BigInteger(f));
//        parameters2.addUint(new BigInteger(role));
//        parameters2.addUint(new BigInteger(purpose));

        // contract request
        CallContractRequest request2 = CallContractRequest.build(testAccount2.getIdentity(), // 调用合约的账户ID
                Utils.getIdentityByName(testContractId, env), // 被调用的合约ID
                parameters2, // 被调用的合约接口及其需要的参数
                BigInteger.ZERO, // 值（是不是交易的金额？）
                params2, // 链的参数
                0, // 时间戳（不造干啥）
                0, // 时长（不造干啥）
                BaseFixedSizeUnsignedInteger.Fixed64BitUnsignedInteger.valueOf(BigInteger.ONE)); // 不造干啥的

        // call contract
        MychainBaseResult<ReplyTransactionReceipt> callContractResult = sdk.getContractService().callContract(request2);
        System.out.println(callContractResult.isSuccess());
        System.out.println(callContractResult.getData().getTransactionReceipt().getResult());
        if (!callContractResult.isSuccess() || callContractResult.getData().getTransactionReceipt().getResult() != 0) {
            exit("verify", getErrorMsg((int)callContractResult.getData().getTransactionReceipt().getResult()));
        } else {
            System.out.println("verify " + role + " for purpose " + purpose + " success!");
//            System.out.println("verify " + String.valueOf(role)+String.valueOf(purpose));
        }

        String txHash2 = callContractResult.getTxHash();
        System.out.println(txHash2);
        return txHash2;

        //TransactionReceipt a = callContractResult.getData().getTransactionReceipt();
        //byte[] b = a.getOutput();
        //List<LogEntry> c = a.getLogs();
    }


    
}
