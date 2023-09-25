package com.example.springsecurity.repository;


import com.example.springsecurity.domain.Article;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlogRepository extends JpaRepository<Article, Long> {
}

