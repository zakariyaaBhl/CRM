<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
  	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
	<meta charset="utf-8">
<title>Home Page</title>
</head>
<body>
	<br>
	<div class="container col-md-10 col-md-offset-1">
	
		<!-- Static navbar -->
      <nav class="navbar navbar-default">
        <div class="container-fluid">
          <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
              <span class="sr-only">Toggle navigation</span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
              <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="${pageContext.request.contextPath}/">Show Room</a>
          </div>
          <div id="navbar" class="navbar-collapse collapse">
            <ul class="nav navbar-nav">
              <li class="active"><a href="${pageContext.request.contextPath}/">Home</a></li>
              
              
              <li class="dropdown">
			    <a href="${pageContext.request.contextPath}/show" class=" dropdown-toggle" type="button" id="menu1" data-toggle="dropdown">Products
			    <span class="caret"></span></a>
			    <ul class="dropdown-menu" role="menu" aria-labelledby="menu1">
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="${pageContext.request.contextPath}/show">All Products</a></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="${pageContext.request.contextPath}/addForm">Add new Product</a></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="#">CSS</a></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="#">JavaScript</a></li>
			      <li role="presentation" class="divider"></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="#">About Us</a></li>
			    </ul>
			  </li>
			  
			  <li class="dropdown">
			    <a href="${pageContext.request.contextPath}/show" class=" dropdown-toggle" type="button" id="menu1" data-toggle="dropdown">Categories
			    <span class="caret"></span></a>
			    <ul class="dropdown-menu" role="menu" aria-labelledby="menu1">
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="${pageContext.request.contextPath}/show">All Categories</a></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="${pageContext.request.contextPath}/addForm">Add new Category</a></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="#">CSS</a></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="#">JavaScript</a></li>
			      <li role="presentation" class="divider"></li>
			      <li role="presentation"><a role="menuitem" tabindex="-1" href="#">About Us</a></li>
			    </ul>
			  </li>
              
              <li><a href="${pageContext.request.contextPath}/about">About</a></li>
              <li><a href="${pageContext.request.contextPath}/contact">Contact</a></li>
              
              
            </ul>
            <ul class="nav navbar-nav navbar-right">
              <li class="active"><a href="${pageContext.request.contextPath}/logout" class="btn btn-default">Sign Out<span class="sr-only">(current)</span></a></li>
              
            </ul>
          </div><!--/.nav-collapse -->
        </div><!--/.container-fluid -->
      </nav>


		<div>
			<h2 class="text-link text-center label-info">DashBoard</h2>
		</div>
	</div>
</body>
</html>