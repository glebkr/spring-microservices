package org.example.customer.api;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.customer.model.CustomerRegistrationRequest;
import org.example.customer.service.CustomerService;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/customers")
@AllArgsConstructor
@Slf4j
public class CustomerController {

    private final CustomerService customerService;
    private final AmqpTemplate amqpTemplate;

    @PostMapping
    public void registerCustomer(@RequestBody CustomerRegistrationRequest customerRegistrationRequest) {
        log.info("new customer registration {}", customerRegistrationRequest);
        customerService.registerCustomer(customerRegistrationRequest);
    }
}
