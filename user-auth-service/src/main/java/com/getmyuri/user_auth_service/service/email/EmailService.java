package com.getmyuri.user_auth_service.service.email;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import static com.getmyuri.user_auth_service.common.constants.EmailConstants.ACTIVATION_CODE;
import static com.getmyuri.user_auth_service.common.constants.EmailConstants.CONFIRMATION_URL;
import static com.getmyuri.user_auth_service.common.constants.EmailConstants.DEFAULT_TEMPLATE_NAME;
import static com.getmyuri.user_auth_service.common.constants.EmailConstants.USERNAME;
import com.getmyuri.user_auth_service.model.email.EmailTemplateName;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Async
    public void sendEmail(String to, String username,
            EmailTemplateName emailTemplate, String confirmation,
            String activationCode, String subject) throws MessagingException {
        String templateName;
        if (emailTemplate == null) {
            templateName = DEFAULT_TEMPLATE_NAME;
        } else {
            templateName = emailTemplate.name();
        }
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage,
                MimeMessageHelper.MULTIPART_MODE_MIXED,
                StandardCharsets.UTF_8.name());

        Map<String, Object> properties = new HashMap<>();
        properties.put(USERNAME, username);
        properties.put(CONFIRMATION_URL, helper);
        properties.put(ACTIVATION_CODE, activationCode);

        Context context = new Context();
        context.setVariables(properties);
        helper.setFrom("contact@getmyuri.com");
        helper.setTo(to);
        helper.setSubject(subject);

        String template = templateEngine.process(templateName, context);

        helper.setText(template, Boolean.TRUE);
        mailSender.send(mimeMessage);

    }

}
