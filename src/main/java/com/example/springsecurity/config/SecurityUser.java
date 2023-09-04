package com.example.springsecurity.config;

import com.example.springsecurity.domain.Member;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;


public class SecurityUser extends User {
	private static final long serialVersionUID = 1L;

	public SecurityUser(Member member) {
		super(member.getId(), member.getPassword(),
				AuthorityUtils.createAuthorityList(member.getRole().toString()));
	}
}
