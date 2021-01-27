package org.fisco.bcos.asset.client;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.List;
import java.util.Properties;
import org.fisco.bcos.asset.contract.Authentication;
import org.fisco.bcos.sdk.BcosSDK;
import org.fisco.bcos.sdk.abi.datatypes.generated.tuples.generated.Tuple4;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.fisco.bcos.sdk.crypto.CryptoSuite;
import org.fisco.bcos.sdk.model.CryptoType;
import org.fisco.bcos.sdk.crypto.hash.Keccak256;
import org.fisco.bcos.sdk.crypto.signature.ECDSASignatureResult;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

public class AuthenticationClient {

  static Logger logger = LoggerFactory.getLogger(AuthenticationClient.class);

  private BcosSDK bcosSDK;
  private Client client;
  private CryptoKeyPair cryptoKeyPair;

  public void initialize() throws Exception {
    @SuppressWarnings("resource")
    ApplicationContext context =
        new ClassPathXmlApplicationContext("classpath:applicationContext.xml");
    bcosSDK = context.getBean(BcosSDK.class);
    client = bcosSDK.getClient(1);
    cryptoKeyPair = client.getCryptoSuite().createKeyPair();
    client.getCryptoSuite().setCryptoKeyPair(cryptoKeyPair);
    logger.debug("create client for group1, account address is " + cryptoKeyPair.getAddress());
  }

  public void deployAuthenticationAndRecordAddr() {

    try {
      Authentication auth = Authentication.deploy(client, cryptoKeyPair);
      System.out.println(
          " deploy Authentication success, contract address is " + auth.getContractAddress());

      recordAuthenticationAddr(auth.getContractAddress());
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      System.out.println(" deploy Authentication contract failed, error message is  " + e.getMessage());
    }
  }


  public void recordAuthenticationAddr(String address) throws FileNotFoundException, IOException {
    Properties prop = new Properties();
    prop.setProperty("address", address);
    final Resource contractResource = new ClassPathResource("contract.properties");
    FileOutputStream fileOutputStream = new FileOutputStream(contractResource.getFile());
    prop.store(fileOutputStream, "contract address");
  }

  public String loadAuthenticationAddr() throws Exception {
    // load Asset contact address from contract.properties
    Properties prop = new Properties();
    final Resource contractResource = new ClassPathResource("contract.properties");
    prop.load(contractResource.getInputStream());

    String contractAddress = prop.getProperty("address");
    if (contractAddress == null || contractAddress.trim().equals("")) {
      throw new Exception(" load Authentication contract address failed, please deploy it first. ");
    }
    logger.info(" load Authentication address from contract.properties, address is {}", contractAddress);
    return contractAddress;
  }

  // generate secp256k1 signature
  public ECDSASignatureResult  generateSigantureWithSecp256k1(String data){
    CryptoSuite cryptoSuite = new CryptoSuite(CryptoType.ECDSA_TYPE);
    //CryptoKeyPair cryptoKeyPair = cryptoSuite.createKeyPair();
    String hashData = cryptoSuite.hash(data);
    System.out.println(
          " hash data to be signed:" + hashData);
    return (ECDSASignatureResult)(cryptoSuite.sign(hashData, cryptoKeyPair));
  }

  public void loginAuthenticationAddress(String accountId) {
    try {
      long startTime = System.currentTimeMillis();
      String contractAddress = loadAuthenticationAddr();
      Authentication auth = Authentication.load(contractAddress, client, cryptoKeyPair);
      Tuple4<BigInteger, String, String, String> result = auth.select(accountId);
      if (result.getValue1().compareTo(new BigInteger("0")) == 0) {
        System.out.println("---------1. verify the validity of the account data on the blockchain--------");
        String tmpPublicKey =  result.getValue2();
        String UserInfo =  result.getValue3();
        String tmpsigdata =  result.getValue4();
        CryptoSuite cryptoSuite = new CryptoSuite(CryptoType.ECDSA_TYPE);
        String tmpdataToBeVrified = accountId +  UserInfo +  tmpPublicKey;
        String hashData = cryptoSuite.hash(tmpdataToBeVrified);
        boolean nVerification = cryptoSuite.verify(tmpPublicKey, hashData, tmpsigdata);
        if(nVerification){
          long verifyAccountDataTime = System.currentTimeMillis() - startTime;
          System.out.printf("Account data is Valid.verifyAccountDataTime=%d\n",verifyAccountDataTime);
          System.out.println("---------2. generate a token to be signed by the user--------");
          long timeStamp = System.currentTimeMillis();
          String dataToBeSigned =  accountId  + timeStamp + cryptoKeyPair.getHexPublicKey();
          System.out.println("---------3. the user signed the token data-------");
          ECDSASignatureResult sigdata = generateSigantureWithSecp256k1(dataToBeSigned);
          long sigTokenTime = System.currentTimeMillis() - startTime - verifyAccountDataTime;
          System.out.printf("sigTokenTime=%d\n",sigTokenTime);
          System.out.println("---------4. verify the validity of token data-------");
          long expireTime = System.currentTimeMillis() - timeStamp;
          if(expireTime > (5*60*1000)){
            System.out.println("Expired. Reject the request. \n");
          }else{
             dataToBeSigned = cryptoSuite.hash(dataToBeSigned);
             nVerification = cryptoSuite.verify(cryptoKeyPair.getHexPublicKey(), dataToBeSigned, sigdata.convertToString());
             if(nVerification){
              System.out.printf("login success \n");
              long verifyTokenTime = System.currentTimeMillis() - startTime - verifyAccountDataTime - sigTokenTime;
              System.out.printf("verifyTokenTime=%d\n",verifyTokenTime);
             }else{
               System.out.println("token invalid. Reject the login. \n");
             }
          }

        }else{
          System.out.printf("The account data is invalid  \n");
        }
      
      } else {
        System.out.printf(" %s Authentication account is not exist \n", accountId);
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      logger.error(" login AuthenticationAddress exception, error message is {}", e.getMessage());

      System.out.printf(" login Authentication account failed, error message is %s\n", e.getMessage());
    }
  }
  
  public static String getRandomString(int length){
     String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
     Random random=new Random();
     StringBuffer sb=new StringBuffer();
     for(int i=0;i<length;i++){
       int number=random.nextInt(62);
       sb.append(str.charAt(number));
     }
     return sb.toString();
  } 


  public void batchloginAuthenticationAddress(int amount){
     System.out.println("----Experiment on query the users' public key. Qurey for a non-existed account id will fail.----");
     try {
      String contractAddress = loadAuthenticationAddr();
      Authentication auth = Authentication.load(contractAddress, client, cryptoKeyPair);
      Random r = new Random();
      String [] user = new String[amount];
      long startTime = System.currentTimeMillis();
      long querySuccess = 0;
      long queryFail = 0;
      long queryTotal = 0;

      
      for(int i=0 ; i< amount;  i++){
         long istartTime = System.currentTimeMillis();
         int ran1 = r.nextInt(amount);
         user[i] = "user" + Integer.toString(ran1);
         Tuple4<BigInteger, String, String, String> result = auth.select(user[i]);
          if (result.getValue1().compareTo(new BigInteger("0")) == 0) {
            System.out.printf(" Authentication accountID %s, PublicKey %s \n", user[i], result.getValue2());
            long ielapsed = System.currentTimeMillis() - istartTime;
            double isendSpeed = 1 / ((double) ielapsed / 1000);
            querySuccess ++;
          } else {
            queryFail ++;
            System.out.printf(" %s Authentication account is not exist \n", user[i]);
          }
          queryTotal ++;
      
      }

      long elapsed = System.currentTimeMillis() - startTime;
      double sendSpeed = queryTotal / ((double) elapsed / 1000);
      double reject = ((double)queryFail) / ((double)queryTotal) * 100.0;
      double accept = ((double)querySuccess) / ((double)queryTotal) * 100.0;
      System.out.printf(
        "%s tests in the query experiment. %.1f%% Success. %.1f%% failed because Authentication account is not exist. \n TotalTime=%d ms .\n QPS=%f \n",queryTotal,accept,reject,elapsed,sendSpeed);




      
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      logger.error(" loginAuthenticationAddress exception, error message is {}", e.getMessage());

      System.out.printf("login account failed, error message is %s\n", e.getMessage());
    }
  }



  public void batchRegister(int amount){
    try {

      System.out.println("----Experiment on registering users at random. Registrations with a existed account id will fail.----");
      String contractAddress = loadAuthenticationAddr();
      Authentication auth = Authentication.load(contractAddress, client, cryptoKeyPair);
      System.out.println("Generating account id and its corresponding public key at random.");
        
      Random r = new Random();
      String [] user = new String[amount];
      long startTime = System.currentTimeMillis();
      long regSuccess = 0;
      long regFail = 0;
      long regTotal = 0;
      
      for(int i=0 ; i< amount;  i++){
         long istartTime = System.currentTimeMillis();
         int ran1 = r.nextInt(amount);
         user[i] = "batchtestuser" + Integer.toString(ran1);
         String PublicKey = cryptoKeyPair.getHexPublicKey();
         String UserInfo = "Phone+1667727772;Hobby:Football";
         String dataToBeSigned =  user[i]  + UserInfo + PublicKey;
         ECDSASignatureResult sigdata = generateSigantureWithSecp256k1(dataToBeSigned);
         TransactionReceipt receipt = auth.register(user[i], PublicKey,UserInfo,sigdata.convertToString());
         List<Authentication.RegisterEventEventResponse> response = auth.getRegisterEventEvents(receipt);
         if (!response.isEmpty()) {
            if (response.get(0).ret.compareTo(new BigInteger("0")) == 0) {
              System.out.printf(
                  " register Authentication account success => Authentication: %s, value: %s \n", user[i], PublicKey);
              long ielapsed = System.currentTimeMillis() - istartTime;
              double isendSpeed = 1 / ((double) ielapsed / 1000);
              regSuccess ++;
            } else {
              regFail ++;
              System.out.printf(
                  " register Authentication account failed, ret code is %s \n", response.get(0).ret.toString());
            }
          } else {
            System.out.println(" event log not found, maybe transaction not exec. ");
          }
         regTotal ++;
         }
     
      long elapsed = System.currentTimeMillis() - startTime;
      double sendSpeed = regTotal / ((double) elapsed / 1000);
      double reject = ((double)regFail) / ((double)regTotal) * 100.0;
      double accept = ((double)regSuccess) / ((double)regTotal) * 100.0;
      System.out.printf(
        "%s tests in the register experiment. %.1f%% Success. %.1f%% failed for using the illegal id. \n TotalTime=%d ms .\n TPS=%f \n",regTotal,accept,reject,elapsed,sendSpeed);

      
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();
      logger.error(" registeAuthenticationAccount exception, error message is {}", e.getMessage());
      System.out.printf(" register Authentication account failed, error message is %s\n", e.getMessage());
    }
  }
  public void registerAuthenticationAccount(String AccountId, String PublicKey, String UserInfo, String SigData) {
    try {

      System.out.println("begin register... ");
      long startTime = System.currentTimeMillis();
      String contractAddress = loadAuthenticationAddr();

      Authentication auth = Authentication.load(contractAddress, client, cryptoKeyPair);
      TransactionReceipt receipt = auth.register(AccountId, PublicKey, UserInfo, SigData);
      List<Authentication.RegisterEventEventResponse> response = auth.getRegisterEventEvents(receipt);
      if (!response.isEmpty()) {
        if (response.get(0).ret.compareTo(new BigInteger("0")) == 0) {
          System.out.printf(
              " register Authentication account success => Authentication: %s, value: %s \n", AccountId, PublicKey);
          long elapsed = System.currentTimeMillis() - startTime;
          //double sendSpeed = ((double) elapsed / 1000);
          //System.out.println("TotalTime="+ elapsed);
        } else {
          System.out.printf(
              " register Authentication account failed, ret code is %s \n", response.get(0).ret.toString());
        }
      } else {
        System.out.println(" event log not found, maybe transaction not exec. ");
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      // e.printStackTrace();

      logger.error(" registeAuthenticationAccount exception, error message is {}", e.getMessage());
      System.out.printf(" register Authentication account failed, error message is %s\n", e.getMessage());
    }
  }


  public static void Usage() {
    System.out.println(" Usage:");
    System.out.println(
        "\t java -cp conf/:lib/*:apps/* org.fisco.bcos.asset.client.AuthenticationClient deploy");
    System.out.println(
        "\t java -cp conf/:lib/*:apps/* org.fisco.bcos.asset.client.AuthenticationClient query account");
    System.out.println(
        "\t java -cp conf/:lib/*:apps/* org.fisco.bcos.asset.client.AuthenticationClient register account value");
    System.out.println(
        "\t java -cp conf/:lib/*:apps/* org.fisco.bcos.asset.client.AuthenticationClient mquery number");
    System.out.println(
        "\t java -cp conf/:lib/*:apps/* org.fisco.bcos.asset.client.AuthenticationClient mregister number");
    System.exit(0);
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      Usage();
    }

    AuthenticationClient client = new AuthenticationClient();
    client.initialize();

    switch (args[0]) {
      case "deploy":
        client.deployAuthenticationAndRecordAddr();
        break;
      case "login":
        if (args.length < 2) {
          Usage();
        }
        client.loginAuthenticationAddress(args[1]);
        break;
      case "mlogin":
        if (args.length < 2) {
          Usage();
        }
        client.batchloginAuthenticationAddress(Integer.valueOf(args[1]).intValue());
        break;
      case "register":
        if (args.length < 5) {
          Usage();
        }
        client.registerAuthenticationAccount(args[1], new String(args[2]), new String(args[3]), new String(args[4]));
        break;
      case "mregister":
         if (args.length < 2) {
          Usage();
         }
         client.batchRegister(Integer.valueOf(args[1]).intValue());
         break;
      default:
        {
          Usage();
        }
    }
    System.exit(0);
  }
}


