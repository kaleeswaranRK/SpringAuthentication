package com.springauth.model;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springauth.service.JwtTokenUtil;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationManager authenticationManager;
	private final UserDetailsService userDetailsService;
	private final JwtTokenUtil jwtTokenUtil;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager, UserDetailsService userDetailsService,
			JwtTokenUtil jwtTokenUtil) {
		this.authenticationManager = authenticationManager;
		this.userDetailsService = userDetailsService;
		this.jwtTokenUtil = jwtTokenUtil;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String header = request.getHeader("Authorization");

		if (header == null || !header.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = header.replace("Bearer ", "");

		try {
			// Extract username from token
			String username = jwtTokenUtil.extractUsername(token);

			if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				// Verify token expiration
				if (!jwtTokenUtil.validateToken(token, userDetailsService.loadUserByUsername(username))) {
					// Token is not valid or expired
					response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					return;
				}

				// Token is valid, continue with authentication
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);

				if (userDetails != null && userDetails.isEnabled()) {
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			}
		} catch (Exception e) {
			// Handle exceptions
			logger.error("Error processing authentication token: " + e.getMessage());
			// You can send an appropriate HTTP response or log a message
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}

		filterChain.doFilter(request, response);
	}

}
