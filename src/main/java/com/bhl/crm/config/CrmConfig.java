package com.bhl.crm.config;

import java.beans.PropertyVetoException;
import java.util.Properties;

import javax.sql.DataSource;
import org.jboss.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.orm.hibernate5.HibernateTransactionManager;
import org.springframework.orm.hibernate5.LocalSessionFactoryBean;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import com.mchange.v2.c3p0.ComboPooledDataSource;

@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.bhl.crm")
@PropertySource({"classpath:persistence-mysql.properties","classpath:security-persistence-mysql.properties"})
@EnableTransactionManagement
public class CrmConfig implements WebMvcConfigurer{
	
	@Autowired
	 private Environment env;
	private Logger logger = Logger.getLogger(getClass().getName());
	
	@Bean
	public ViewResolver viewResolver() {
		InternalResourceViewResolver viewResolver= new InternalResourceViewResolver();
		viewResolver.setPrefix("/WEB-INF/view/");
		viewResolver.setSuffix(".jsp");
		return viewResolver;
	}
	
	@Bean
	public DataSource productDataSource() {
		ComboPooledDataSource productDataSource= new ComboPooledDataSource();
		try {
			productDataSource.setDriverClass(env.getProperty("jdbc.driver"));
			
			logger.info("\n===>>url : "+forDB("jdbc.url"));
			logger.info("\n===>>username : "+forDB("jdbc.user"));
			
			productDataSource.setJdbcUrl(forDB("jdbc.url"));
			productDataSource.setUser(forDB("jdbc.user"));
			productDataSource.setPassword(forDB("jdbc.password"));
			
			productDataSource.setInitialPoolSize(forConnectionPool("connection.pool.initialPoolSize"));
			productDataSource.setMinPoolSize(forConnectionPool("connection.pool.minPoolSize"));
			productDataSource.setMaxPoolSize(forConnectionPool("connection.pool.maxPoolSize"));
			productDataSource.setMaxIdleTime(forConnectionPool("connection.pool.maxIdleTime"));
			
			
		} catch (PropertyVetoException e) {
			new RuntimeException(e);
		}
		
		return productDataSource;
	}
	
	@Bean
	public DataSource securityDataSource() {
		ComboPooledDataSource securityDataSource = new ComboPooledDataSource();
		try {
			securityDataSource.setDriverClass(env.getProperty("security.jdbc.driver"));
			
			logger.info("\n====>>>>>security.url=" + env.getProperty("security.jdbc.url"));
			logger.info("\n====>>>>>security.user=" + env.getProperty("security.jdbc.user"));
			
			securityDataSource.setJdbcUrl(env.getProperty("security.jdbc.url"));
			securityDataSource.setUser(env.getProperty("security.jdbc.user"));
			securityDataSource.setPassword(env.getProperty("security.jdbc.password"));
			
			securityDataSource.setInitialPoolSize(Integer.parseInt(env.getProperty("security.connection.pool.initialPoolSize")));
			securityDataSource.setMinPoolSize(Integer.parseInt(env.getProperty("security.connection.pool.minPoolSize")));
			securityDataSource.setMaxPoolSize(Integer.parseInt(env.getProperty("security.connection.pool.maxPoolSize")));
			securityDataSource.setMaxIdleTime(Integer.parseInt(env.getProperty("security.connection.pool.maxIdleTime")));
			
		} catch (PropertyVetoException e) {
			new RuntimeException(e);
		}
		
		return securityDataSource;
	}
	
	/*-- The next method handles the Hibernate properties --*/
	private Properties getHibernateProperties() {
		/*-- set hibernate properties --*/
		Properties properties = new Properties();
		properties.setProperty("hibernate.dialect", env.getProperty("hibernate.dialect"));
		properties.setProperty("hibernate.hbm2ddl.auto", "update");
		properties.setProperty("hibernate.show_sql", env.getProperty("hibernate.show_sql"));
		return properties;
	}
	
	/*-- 
	 * The next method creates the Hibernate session factory based on the datasource and configuration properties
	 * Setup Hibernate session factory : session factory is what hibernate uses to talk to our DB 
	 * --*/
	
	@Bean
	public LocalSessionFactoryBean getSessionFactory() {
		LocalSessionFactoryBean factory= new LocalSessionFactoryBean();
		factory.setDataSource(productDataSource());
		factory.setPackagesToScan("com.bhl.crm.entities");
		factory.setHibernateProperties(getHibernateProperties());
		
		
		return factory;
	}
	
	/*-- The next method configures the Hibernate transaction manager --*/
	
	@Bean
	public HibernateTransactionManager transactionManager() {
		HibernateTransactionManager transactionManager = new HibernateTransactionManager();
		transactionManager.setSessionFactory(getSessionFactory().getObject());
		return transactionManager;
	}
	
	
	
	
	
	
	/*-- Methods help to reduce code java --*/
	public String forDB(String property) {
		return env.getProperty(property);
	}
	
	public Integer forConnectionPool(String property) {
		return Integer.parseInt(env.getProperty(property));
	}
	
}
