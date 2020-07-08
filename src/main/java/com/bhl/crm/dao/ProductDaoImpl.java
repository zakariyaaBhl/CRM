package com.bhl.crm.dao;

import java.util.List;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.bhl.crm.entities.Product;


@Repository
@Transactional
public class ProductDaoImpl implements IProductDao {

	@Autowired
	private SessionFactory factory;
	
	public List<Product> getAllProducts() {
		Session session=factory.getCurrentSession();
		Query<Product> query = session.createQuery("from Product p", Product.class);
		List<Product> prods=query.getResultList();
		return prods;
	}

	public Product getProductbyId(Long id) {
		Session session=factory.getCurrentSession();
		Product p = session.get(Product.class, id);
		return p;
	}

	public List<Product> getProductbyMc(String mc) {
		Session session=factory.getCurrentSession();
		Query<Product> query = session.createQuery("from Product p where p.designation =: mc", Product.class);
		query.setParameter("mc", mc);
		query.executeUpdate();
		List<Product> prods=query.getResultList();
		return prods;
	}

	public Product save(Product p) {
		Session session=factory.getCurrentSession();
		session.saveOrUpdate(p);
		return p;
	}

	public Product update(Product p) {
		Session session=factory.getCurrentSession();
		session.update(p);
		return null;
	}

	public void delete(Long id) {
		Session session = factory.getCurrentSession();
		session.delete(session.get(Product.class, id));

	}

}
