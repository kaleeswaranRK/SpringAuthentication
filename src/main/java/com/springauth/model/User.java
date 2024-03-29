package com.springauth.model;

public class User {

	private Long id;
	private String userName;
	private String password;
	private String Authorities;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getAuthorities() {
		return Authorities;
	}

	public void setAuthorities(String authorities) {
		Authorities = authorities;
	}

	public User(Long id, String userName, String password, String authorities) {
		super();
		this.id = id;
		this.userName = userName;
		this.password = password;
		Authorities = authorities;
	}

}
