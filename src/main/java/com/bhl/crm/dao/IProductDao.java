package com.bhl.crm.dao;

import java.util.List;

import com.bhl.crm.entities.Product;

public interface IProductDao {
	public List<Product> getAllProducts();
	public Product getProductbyId(Long id);
	public List<Product> getProductbyMc(String mc);
	public Product save(Product p);
	public Product update(Product p);
	public void delete(Long id);
}
