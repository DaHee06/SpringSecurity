package com.example.springsecurity.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter 
@Setter
@ToString
@Entity
public class Member { 
	@Id
	private String id; 
	private String password;
	private String name;
	@Enumerated(EnumType.STRING)
	private Role role;
//	private boolean enabled;
}
