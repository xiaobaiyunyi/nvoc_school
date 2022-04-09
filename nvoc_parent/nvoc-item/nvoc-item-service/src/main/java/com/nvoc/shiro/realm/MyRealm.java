package com.nvoc.shiro.realm;

import com.auth0.jwt.interfaces.Claim;
import com.nvoc.service.AdminService;
import com.nvoc.service.StudentService;
import com.nvoc.service.TeacherService;
import com.nvoc.shiro.token.JwtToken;
import com.zjl.legou.common.utils.JwtUtil;
import lombok.SneakyThrows;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.checkerframework.checker.units.qual.A;
import org.springframework.beans.factory.annotation.Autowired;

public class MyRealm extends AuthorizingRealm {

    @Autowired
    private StudentService studentService;

    @Autowired
    private TeacherService teacherService;

    @Autowired
    private AdminService adminService;

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    /**
     * 验证相关
     * Long
     * 2022年4月9日
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        JwtToken token = (JwtToken) authenticationToken;
        String principal = (String) token.getPrincipal();
        try {
            String role = JwtUtil.verify(principal).getClaim("role").asString();
            if (role.equals("student")){

                return new SimpleAuthenticationInfo();
            }else if (role.equals("teacher")){

                return new SimpleAuthenticationInfo();
            }

            return new SimpleAuthenticationInfo();
        }catch (Exception e){
            e.printStackTrace();
            throw new UnknownAccountException("用户认证出错！");
        }
    }
}
