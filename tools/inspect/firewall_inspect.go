package main

import (
	"fmt"
	"reflect"

	"github.com/crowdstrike/gofalcon/falcon/client"
)

func main() {
	// Create empty client just to inspect type methods
	emptyClient := &client.CrowdStrikeAPISpecification{}

	fmt.Println("=== Firewall Policies API ===")
	inspectFirewallPolicies(emptyClient)

	fmt.Println("\n=== Firewall Management API ===")
	inspectFirewallManagement(emptyClient)
}

func inspectFirewallPolicies(client *client.CrowdStrikeAPISpecification) {
	// Check available operations
	fmt.Println("--- Available Firewall Policy Operations ---")
	t := reflect.TypeOf(client.FirewallPolicies)
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		fmt.Printf("- %s\n", method.Name)
	}
}

func inspectFirewallManagement(client *client.CrowdStrikeAPISpecification) {
	// Check available operations
	fmt.Println("--- Available Firewall Management Operations ---")
	t := reflect.TypeOf(client.FirewallManagement)
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		fmt.Printf("- %s\n", method.Name)
	}
}

func printStructure(v interface{}, indent string) {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	typ := val.Type()
	
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		
		if !field.CanInterface() {
			continue
		}
		
		fmt.Printf("%s%s: ", indent, fieldType.Name)
		
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			fmt.Printf("%v\n", field.Elem().Interface())
		} else if field.Kind() == reflect.Slice && field.Len() > 0 {
			fmt.Printf("[%d items]\n", field.Len())
		} else if field.CanInterface() {
			fmt.Printf("%v\n", field.Interface())
		} else {
			fmt.Printf("<unexported>\n")
		}
	}
}