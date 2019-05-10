package com.yidong.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

/**
 * Created by Administrator on 2019/2/12.
 */
@Configuration
@PropertySource("classpath:config/myconfig.properties")
public class PropConf {

    @Value("${port}")
    private String port;
    @Value("${address}")
    private String address;

    public void show(){
        System.out.println("port --- > " + port);
        System.out.println("address --- > " + address);
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
}
