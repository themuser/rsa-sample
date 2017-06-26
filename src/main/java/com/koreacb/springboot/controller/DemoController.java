package com.koreacb.springboot.controller;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.koreacb.springboot.service.DemoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Myungkyo Jung
 */
@RestController
public class DemoController {

    private static final Logger logger = LoggerFactory.getLogger(DemoController.class);

    @Resource
    private DemoService demoService;

    @RequestMapping("/hello")
    public String sayHello(){
        logger.debug("This is demo controller.");
        return "Hello, world!";
    }

    @RequestMapping(value="/exchange", produces={"application/json"})
    @ResponseBody
    public String handshake() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Map<String, String> map = demoService.generateKeyPair();
        return new GsonBuilder().create().toJson(map);
    }

    @RequestMapping("/decrypt")
    @ResponseBody
    public String decrypt(@RequestParam final String publicKey, @RequestParam final String encrypted) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        logger.debug("Public Key String: " + publicKey);
        logger.debug("Encrypted String: " + encrypted);

        demoService.decrypt(publicKey, encrypted);

        return "";
    }
}
