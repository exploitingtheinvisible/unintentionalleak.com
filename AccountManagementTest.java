qatest.java

import org.junit.*;
import org.openqa.selenium.*;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions;
import java.util.concurrent.TimeUnit;

public class AccountManagementTest {

    // WebDriver instance
    WebDriver driver;

    // Test setup: initializing WebDriver before each test
    @Before
    public void setUp() {
        // Set path to your ChromeDriver
        System.setProperty("webdriver.chrome.driver", "path_to_your_chromedriver");
        driver = new ChromeDriver();
        driver.manage().timeouts().implicitlyWait(10, TimeUnit.SECONDS);
    }

    // Test case for User Registration
    @Test
    public void testUserRegistration() {
        driver.get("https://yourinsuranceapp.com/register");
        
        // Fill in registration form
        driver.findElement(By.id("first_name")).sendKeys("Jack");
        driver.findElement(By.id("last_name")).sendKeys("Reacher");
        driver.findElement(By.id("email")).sendKeys("jack@unintentionalleak.com");
        driver.findElement(By.id("phone")).sendKeys("1234567890");
        driver.findElement(By.id("password")).sendKeys("Password123!");
        driver.findElement(By.id("confirm_password")).sendKeys("Password123!");
        
        // Agree to terms
        driver.findElement(By.id("terms")).click();
        
        // Submit registration form
        driver.findElement(By.id("register_button")).click();

        // Wait for redirection to login or dashboard page
        new WebDriverWait(driver, 10).until(ExpectedConditions.urlContains("dashboard"));
        
        // Verify registration success by checking page URL or any user-specific element
        Assert.assertTrue(driver.getCurrentUrl().contains("dashboard"));
    }

    // Test case for User Login
    @Test
    public void testUserLogin() {
        driver.get("https://yourinsuranceapp.com/login");

        // Log in with valid credentials
        driver.findElement(By.id("email")).sendKeys("jack@unintentionalleak.com");
        driver.findElement(By.id("password")).sendKeys("Password123!");
        driver.findElement(By.id("login_button")).click();

        // Wait for dashboard to load
        new WebDriverWait(driver, 10).until(ExpectedConditions.visibilityOfElementLocated(By.id("user_dashboard")));

        // Verify successful login
        String userName = driver.findElement(By.id("user_name")).getText();
        Assert.assertEquals("John Doe", userName);
    }