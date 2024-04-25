package app.util;

import app.config.Menu;
import app.model.UserAccount;
import java.nio.file.Paths;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Time;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import javax.mail.*;
import javax.mail.internet.*;
import jakarta.persistence.*;
import jakarta.servlet.http.HttpServletRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

public class Util {

    private static Menu[] menu;
    private static Map<String, String> props;
    private static Map<String, String> operators;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");
    private static SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
    private static SimpleDateFormat dateTimeFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");

    static {
        operators = new HashMap<String, String>();
        operators.put("c", "like");
        operators.put("e", "=");
        operators.put("g", ">");
        operators.put("ge", ">=");
        operators.put("l", "<");
        operators.put("le", "<=");
    }

    private static HttpServletRequest getRequest() {
        return ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getRequest();
    }

    public static UserAccount getUser(EntityManager em) {
        String name = getRequest().getSession().getAttribute("username") != null ? getRequest().getSession().getAttribute("username").toString() : getRequest().getUserPrincipal().getName();
        return em.createQuery("SELECT u FROM UserAccount u where u.name = :name", UserAccount.class).setParameter("name", name).getSingleResult();
    }

    public static String getOperator(String oper) {
        if (!operators.containsKey(oper)) {
            return "=";
        }
        return operators.get(oper);
    }

    public static boolean isInvalidSearch(List<String> columns, String column) {
        if (column == null) {
            return false;
        }
        return !columns.contains(column);
    }

    public static void sentMail(String type, String email, String token) throws MessagingException {
        sentMail(type, email, token, null);
    }

    public static void sentMail(String type, String email, String token, String user) throws MessagingException {
        String body = props.get("mail." + type);
        body = body.replace("{app_url}", props.get("app.url"));
        body = body.replace("{app_name}", props.get("app.name"));
        body = body.replace("{token}", token);
        if (user != null) {
            body = body.replace("{user}", user);
        }
        String subject = (type == "welcome" ? "Login Information" : (type == "reset" ? "Reset Password" : props.get("app.name") + " message"));
        /* You need to complete the SMTP Server configuration before you can sent mail
        Properties properties = new Properties();
        properties.put("mail.smtp.host", props.get("smtp.host"));
        properties.put("mail.smtp.port", props.get("smtp.port"));
        properties.put("mail.smtp.auth", true);
        properties.put("mail.smtp.starttls.enable", true);
        properties.put("mail.smtp.ssl.protocols", "TLSv1.2");
        properties.put("mail.smtp.ssl.trust", props.get("smtp.host"));
        Session session = Session.getDefaultInstance(properties, new Authenticator() {
            protected PasswordAuthentication  getPasswordAuthentication() {
                return new PasswordAuthentication(props.get("smtp.user"), props.get("smtp.password"));
            }
        });
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(props.get("mail.sender")));
        message.addRecipient(Message.RecipientType.TO,new InternetAddress(email));
        message.setSubject(subject);
        message.setText(body);
        Transport.send(message);
        */
    }

    public static String getRef(String path) {
        String ref = getRequest().getContextPath() + path;
        if (getRequest().getParameter("ref") != null) {
            ref = getRequest().getParameter("ref");
        }
        else if (getRequest().getHeader("referer") != null && getRequest().getParameter("back") == null) {
            ref = getRequest().getHeader("referer");
        }
        if (!ref.endsWith("back=1")) {
            ref += (ref.contains("?") ? "&" : "?") + "back=1";
        }
        return ref;
    }

    public static String getLink(String type, Map<String, Integer> paging, Object value) {
        return Util.getLink(type, paging, value, "");
    }

    public static String getLink(String type, Map<String, Integer> paging, Object value, String sort) {
        HttpServletRequest request = getRequest();
        String link = "";
        if (type.equals("sort")) {
            link = "?page=" + paging.get("current") + "&size=" + paging.get("size") + "&sort=" + value + (((request.getParameter("sort") != null && request.getParameter("sort").equals(value)) || (request.getParameter("sort") == null && sort.equals("asc"))) && request.getParameter("desc") == null ? "&desc=1" : "");
        }
        else if (type.equals("page")) {
            link = "?page=" + value + "&size=" + paging.get("size") + (request.getParameter("sort") != null ? "&sort=" + request.getParameter("sort") + (request.getParameter("desc") != null ? "&desc=1" : ""): "");
        }
        else if (type.equals("size")) {
            link = "?page=1&size=" + value + (request.getParameter("sort") != null ? "&sort=" + request.getParameter("sort") + (request.getParameter("desc") != null ? "&desc=1" : ""): "");
        }
        link += (request.getParameter("sw") != null ? "&sw=" + request.getParameter("sw") + "&sc=" + request.getParameter("sc") + "&so=" + request.getParameter("so") : "");
        return link;
    }

    public static String getSortClass(String column) {
        return Util.getSortClass(column, null);
    }

    public static String getSortClass(String column, String sort) {
        HttpServletRequest request = getRequest();
        return ((request.getParameter("sort") != null && request.getParameter("sort").equals(column)) || (request.getParameter("sort") == null && sort != null) ? (request.getParameter("sort") != null ? (request.getParameter("desc") != null ? "sort desc" : "sort asc") : "sort " + sort) : "sort");
    }

    public static String getFile(String path, MultipartFile filePart) throws IllegalStateException, IOException {
        if (!filePart.isEmpty()) {
            String filename = UUID.randomUUID().toString().substring(24) + "." + StringUtils.getFilenameExtension(filePart.getOriginalFilename());
            File file = Paths.get(props.get("path.upload"), path, filename).toFile();
            while (file.exists()) {
                filename = UUID.randomUUID().toString().substring(24) + "." + StringUtils.getFilenameExtension(filePart.getOriginalFilename());
                file = Paths.get(props.get("path.upload"), path, filename).toFile();
            }
            file.getParentFile().mkdirs();
            filePart.transferTo(file);
            return filename;
        }
        return null;
    }

    public static void setProperties(Environment env) throws Exception {
        props = new HashMap<String, String>();
        props.put("app.name", env.getProperty("app.name"));
        props.put("app.url", env.getProperty("app.url"));
        props.put("smtp.host", env.getProperty("smtp.host"));
        props.put("smtp.port", env.getProperty("smtp.port"));
        props.put("smtp.user", env.getProperty("smtp.user"));
        props.put("smtp.password", env.getProperty("smtp.password"));
        props.put("mail.sender", env.getProperty("mail.sender"));
        props.put("mail.welcome", env.getProperty("mail.welcome"));
        props.put("mail.reset", env.getProperty("mail.reset"));
        props.put("path.upload", env.getProperty("path.upload"));
        Util.menu = new ObjectMapper().readValue(env.getProperty("menu"), Menu[].class);
    }

    public static List<Menu> getMenu() {
        String path = ((String)getRequest().getAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE)).substring(1).split("/")[0];
        GrantedAuthority[] authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities().toArray(new GrantedAuthority[0]);
        List<Menu> userMenu = new ArrayList<Menu>();
        for (Menu item : menu) {
            String[] roles = item.getRoles().split(",");
            for (GrantedAuthority authority : authorities) {
                if (item.getShow() && (item.getRoles().isEmpty() || Arrays.asList(roles).contains(authority.getAuthority()))) {
                    item.setActive(path.equals(item.getPath()));
                    userMenu.add(item);
                    break;
                }
            }
        }
        return userMenu;
    }

    public static String encodeURL(String url) throws UnsupportedEncodingException {
        return URLEncoder.encode(url, "UTF-8");
    }

    public static String getString(byte[] bytes) {
        return (bytes == null ? "" : new String(bytes, StandardCharsets.UTF_8).trim());
    }

    public static String formatDate(Object date) {
        return (date == null ? "" : dateFormat.format(date));
    }

    public static String formatTime(Object time) {
        return (time == null ? "" : timeFormat.format(time));
    }

    public static String formatDateTime(Object date) {
        return (date == null ? "" : dateTimeFormat.format(date));
    }

    public static Object getParameterValue(Map<String, Class<?>> types, String value, String column, String oper) {
        Class<?> cls = types.get(column);
        if (cls == Byte.class) {
            return Byte.valueOf(value);
        }
        else if (cls == Short.class) {
            return Short.valueOf(value);
        }
        else if (cls == Integer.class) {
            return Integer.valueOf(value);
        }
        else if (cls == Double.class) {
            return Double.valueOf(value);
        }
        else if (cls == Float.class) {
            return Float.valueOf(value);
        }
        else if (cls == BigInteger.class) {
            return new BigInteger(value);
        }
        else if (cls == BigDecimal.class) {
            return new BigDecimal(value);
        }
        else if (cls == Date.class) {
            try {
                return (value.length() == dateFormat.toPattern().length() ? dateFormat.parse(value) : dateTimeFormat.parse(value));
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
        else if (cls == Time.class) {
            try {
                return new Time(timeFormat.parse(value).getTime());
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
        else if (cls == Timestamp.class) {
            try {
                return new Timestamp(dateTimeFormat.parse(value).getTime());
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
        else if (cls == Boolean.class) {
            return Boolean.valueOf(value);
        }
        else if (cls == byte[].class) {
            return value.getBytes();
        }
        else if (oper.equals("like")) {
            return "%" + value + "%";
        }
        return value;
    }
}