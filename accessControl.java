package com.example.demo;

import com.alipay.mychain.sdk.api.result.MychainBaseResult;
import com.alipay.mychain.sdk.message.response.ReplyTransaction;
import com.alipay.mychain.sdk.message.response.ReplyTransactionReceipt;
import com.alipay.mychain.sdk.tools.codec.contract.ContractReturnValues;
import com.alipay.mychain.sdk.tools.utils.ByteUtils;

import java.awt.*;
import java.math.BigInteger;

public class accessControl {

    public static void main(String[] args) throws Exception{
        // init environment and account
        init.init();

        // deploy a contract using testAccount1.
        init.deployContract();

        //verify("simmel", "marketing", "marketing");
       // String txHashAdd = init.AddMap("a", "marketing", "marketing");
        int a=1;
        int b=2;
        int c=3;
        String txHashAdd = init.AddMap(a,b);
        System.out.println(txHashAdd);
        MychainBaseResult<ReplyTransaction> txAdd = init.sdk.getQueryService().queryTransaction(txHashAdd);
        MychainBaseResult<ReplyTransactionReceipt> txRecpAdd = init.sdk.getQueryService().queryTransactionReceipt(txHashAdd);

        // 取出从区块链里读出来的调用结果
        byte[] outputRaw1 = new byte[32];
        outputRaw1= txRecpAdd.getData().getTransactionReceipt().getOutput();
        if(outputRaw1[31]==0x01){
            System.out.println("Add success");
        }else {
            System.out.println("Add failed");
        };

        //从前端获取的数据作为veryaccess的参数调用智能合约进行判断

        String txHashVerify=init.verifyAccess(1,7);
        MychainBaseResult<ReplyTransaction> txVerify = init.sdk.getQueryService().queryTransaction(txHashVerify);
        MychainBaseResult<ReplyTransactionReceipt> txRecpVerify = init.sdk.getQueryService().queryTransactionReceipt(txHashVerify);


        // 取出从区块链里读出来的输入数据（用户，角色，意图）
        byte[] inputRaw = new byte[100];
        inputRaw = txVerify.getData().getTransactionDO().getData();

        // 取出从区块链里读出来的调用结果
        byte[] outputRaw = new byte[32];
        outputRaw = txRecpVerify.getData().getTransactionReceipt().getOutput();
        System.out.println(outputRaw);


        //合约的调用结果，如果允许访问 去调用数据库返回客户信息在前端显示，否则前端显示没有权限
        if(outputRaw[31] == 0x01)
            System.out.print("Access is permitted.");

        else
            System.out.print("Access is denied.");

        // 取出从区块链里读出来的交易上链的时间戳
        long timeStamp = txVerify.getData().getTransactionDO().getTimestamp();

        //step 12 : sdk shut down
        init.sdk.shutDown();
    }
}
