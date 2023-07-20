package com.cos.jwt.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    private String roles; // USER, ADMIN

    /*
    getRole 하면 User 나 ADMIN 형태로 반환 될 것이다.
    getRoleList 하면 컬렉션에 USER가 하나 담길거고 ADMIN이 하나 담기니 사이즈가 2개가 됨.
     */

    //내 서버에 Role이 하나라면 아래 메서드 만들 필요 X
    public List<String> getRoleList() {
        if (this.roles.length() > 0) {
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>(); //null 이 안 나오게만 해 놓기
    }
}
