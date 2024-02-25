package com.keycloak.demo.configuration;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken>{

	private KeycloakConfiguration keyCloakProp;
	private JwtGrantedAuthoritiesConverter jwtGAConverter = new JwtGrantedAuthoritiesConverter();
	
	public JwtAuthConverter(KeycloakConfiguration keyCloakProp) {
		super();
		this.keyCloakProp = keyCloakProp;
	}
	
	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {

		Collection<GrantedAuthority> authorities =  Stream.concat(jwtGAConverter.convert(jwt).stream(), 
				extractRoles(jwt).stream()).collect(Collectors.toSet());
		
		return new JwtAuthenticationToken(jwt, authorities, getPrincipalName(jwt) );
	}
	
	private String getPrincipalName(Jwt jwt) {
		String name = JwtClaimNames.SUB;
		if(keyCloakProp.getPrincipleAttribute() != null) {
			name = keyCloakProp.getPrincipleAttribute();
		}
		return jwt.getClaim(name);
		
	}
	
	private Collection<? extends GrantedAuthority> extractRoles(Jwt jwt) {
		Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
		
		Map<String, Object> resource;
		Collection<String> resourceRoles;
		
		if(resourceAccess == null
				|| (resource = (Map<String, Object>) resourceAccess.get(keyCloakProp.getResourceId())) == null
				|| (resourceRoles = (Collection<String>) resource.get("roles")) == null) {
			return Set.of();
			}
		
		return resourceRoles.stream()
		.map(r-> new SimpleGrantedAuthority("ROLE_"+r))
		.collect(Collectors.toSet());
	}
	
	
}
