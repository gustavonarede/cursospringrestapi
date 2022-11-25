package curso.api.rest.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import curso.api.rest.service.ImplementacaoUserDetailsService;

/*mapeia URL, endereços, autoriz ou bloqueia acesso a url*/
@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	private ImplementacaoUserDetailsService implementacaoUserDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// Ativa proteção contra usuários não validados por token
		http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())

		// Ativa permissão para acesso a página inicial
		.disable().authorizeRequests().antMatchers("/").permitAll().antMatchers("/index").permitAll()

		// Liberação do CORS
		.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

		// URL de logout - Redireciona após deslogar do sistema
		.anyRequest().authenticated().and().logout().logoutSuccessUrl("/index")

		// Mapeia URL de logout e invalida o usuário
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout")).and()

		// Filtra requisições de login para autenticação
		
		.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
		// Filtra demais requisições para verificar a presença do TOKEN JWT no HEADER HTTP
		.addFilterBefore(new JwtApiAutenticacaoFilter(), UsernamePasswordAuthenticationFilter.class);
		
		// Amigo, deu certo! :)
		//duas coisas amigo, vc tirou o meu e pois o seu la foi?
		// sim, é que o seu estava faltando algumas coisas, mas se quiser posso voltar o seu e deixar comentado para você não perder o que j
		//n prescisa so uma coisa to finalizando a aula 2.47 eh normal? depois disso alem disso
		// Sim, pois agora você precisa passar o token na requisição
		//so continua a aula neh? sim, vamos ver pelo Postman com o token...
		//desculpa te encomoda neh nao prescisava ser hj ja que vc foi leva sua esposa no medico mas de qualquer maneira muito obrigado ai pelo suporte e desculpa qualquer coisa so isso mesmo pode apaga isso tudo ou nao?
		

	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(implementacaoUserDetailsService).passwordEncoder(new BCryptPasswordEncoder());
	}
	
}
