package com.yidong;

import com.yidong.utils.PropConf;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class SendmessageApplication {

	@RequestMapping("/")
	String index(){
		return "Hello Spring Boot";
	}

	public static void main(String[] args) {
		SpringApplication.run(SendmessageApplication.class, args);
	}

}

