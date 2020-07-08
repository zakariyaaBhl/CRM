package com.bhl.crm.controller;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.bhl.crm.dao.IProductDao;
import com.bhl.crm.entities.Product;

@Controller
public class ShowController {

	@Autowired
	private IProductDao dao;
	
	@GetMapping("/")
	public String showIndex() {
		return "home";
	}
	
	@GetMapping("/show")
	public String showAllProducts(Model model) {
		List<Product> prods = dao.getAllProducts();
		model.addAttribute("products", prods);
		return "products";
	}
	
	@GetMapping("/addForm")
	public String addForm(Model model) {
		model.addAttribute("produit", new Product());
		return "addForm";
	}
	
	@PostMapping("/addProduct")
	public String addProd(@ModelAttribute("prod")@Valid Product p, BindingResult bindingResult, Model model) {
		if (bindingResult.hasErrors()) {
			model.addAttribute("produit", p);
			return "addForm";
		}
		dao.save(p);
		model.addAttribute("produit", p);
		return "redirect:/show";
	}
	
	@GetMapping("/deleteProd")
	public String deleteProd(@RequestParam(name = "id")Long id) {
		dao.delete(id);
		return "redirect:/show";
	}
	
	@GetMapping("/updateForm")
	public String updateForm(Model model, Long id) {
		model.addAttribute("produit", dao.getProductbyId(id));
		return "updateForm";
	}
	
	@PostMapping("/updateProduct")
	public String updateProd(@ModelAttribute("prod")@Valid Product p, BindingResult bindingResult, Model model) {
		if (bindingResult.hasErrors()) {
			model.addAttribute("produit", p);
			return "updateForm";
		}
		dao.save(p);
		model.addAttribute("produit", p);
		return "redirect:/show";
	}
	
	
	
}
