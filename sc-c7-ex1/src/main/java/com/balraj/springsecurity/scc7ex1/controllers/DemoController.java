package com.balraj.springsecurity.scc7ex1.controllers;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping ("/test")
public class DemoController {
    //hasAnyAuthority(), hasAuthority() , hasRole(), hasAnyRole() these can be applied.


    @PreAuthorize("hasAuthority('read')")
    @GetMapping("/test1")
    public String test1() {
        return "test1";
    }


    @PreAuthorize("hasAnyAuthority('write','read')")
    @GetMapping("/test2")
    public String test2() {
        return "test2";
    }




    @GetMapping("/test3/{smth}")
    @PreAuthorize(
            """
                (#something==authentication.name)or 
                hasAnyAuthority('read','write')""")      //authentication is an authenticated object stored in springContext

    //instead of using that large conditions, create a new class and declare a method and inside it use that condition
    // and return a boolean result , since class is bean , directly use it.
    public String test3(@PathVariable("smth") String something) {

        return "test3";
    }
    /*
    controller has only single responsibility of managing the http request,
    the preauthorize is handled using aspects,
     */


    /*
    //{smth} is the path variable placeholder , its a variable, then in the
    //HTTP url, it gets a value,
    /test3/hello
    /test3/123
    /test3/abc
    /test3/anything``` will work,

     */



    @GetMapping("/test4")
    @PreAuthorize("@test4ControllerCondition.condition()")      //to refer to the bean  from spring context use @ , its a
    //SpEL snytax,      and bean name is typically classname with 1st letter lowercase,
    // this way of using for large SpEL is helpful in debugging,you can put a breakpiont
    public String test4(){
        return "test4";
    }



    //PostAuthorize()  used to restrict to access the return value, in it method is always executed
    // it is generally used, when after certain evaluations we get the return object
    // and then decide weather we want to return or not
    @GetMapping("/test5")
    @PostAuthorize("returnObject != 'test5'")     //never use postAuthorize that changes stored Data
    public String test5(){
        System.out.println("Hello World");
        return "test5";
    }


    //PreFilter  => works with either of array or collection(not maps) in the parameter of method
    // it doesn't restrict access of methods (method is always executed) , instead it filters the parameters passed to it
    @GetMapping("/test6")
    @PreFilter("filterObject.contains('a')")    // if there are multiple parameters then we decide the filterObject
    // by filterTarget
    public String test6(@RequestBody List<String> list){
        System.out.println("Values: " + list);
        return "test6";
    }
    // with this you can filter, but remember should be used only for security filtering,
    //like what the authenticated user sends to server and what only server can accept

    // why different authorization logic (pre,post) these can be easily implemented in action method
    // because we want to decouple the security logic and action method


    @GetMapping("/test7")
    @PostFilter("filterObject.contains('a')")  //similar to prefilter but for return values,   it return the filtered values,
    //not returns the unfiltered values
    public List<String> test7(){
        var list = new ArrayList<String>();
        list.add("afsd");
        list.add("tdfd");
        list.add("tgd");
       // return List.of("add","dfd","gdf");    //not works since list.of creates  immutable

        return list;
    }

    //postfilter filter should be related to security concerns

}
