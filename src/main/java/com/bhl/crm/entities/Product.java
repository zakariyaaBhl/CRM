package com.bhl.crm.entities;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.DecimalMin;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "PRODUCT")
public class Product {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ID")
	private Long id;
	
	@Column(name = "DESIGNATION")
	@NotNull
	@Size(min = 5, max = 25)
	private String designation;
	
	@Column(name = "PRIX")
	@DecimalMin("50")
	private double prix;
	
	@Column(name = "QUANTITE")
	@DecimalMin("1")
	private int quantite;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getDesignation() {
		return designation;
	}

	public void setDesignation(String designation) {
		this.designation = designation;
	}

	public double getPrix() {
		return prix;
	}

	public void setPrix(double prix) {
		this.prix = prix;
	}

	public int getQuantite() {
		return quantite;
	}

	public void setQuantite(int quantite) {
		this.quantite = quantite;
	}

	public Product() {
		super();
		// TODO Auto-generated constructor stub
	}

	public Product(String designation, double prix, int quantite) {
		super();
		this.designation = designation;
		this.prix = prix;
		this.quantite = quantite;
	}

	@Override
	public String toString() {
		return "Product [id=" + id + ", designation=" + designation + ", prix=" + prix + ", quantite=" + quantite + "]";
	}
	
	
}
