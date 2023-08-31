package com.example.springsecurity.persistence;

import com.example.springsecurity.domain.Member;
import org.springframework.data.repository.CrudRepository;

public interface MemberRepository extends CrudRepository<Member, String> {
}
