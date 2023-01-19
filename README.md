# Segurança em Spring Boot 3.0.1 com JWT
Este é um projeto básico de segurança em uma aplicação Spring Boot. Em projetos futuros, detalharei e especificarei alguns pormenores.
<h1>Features</h1>
<li>Cadastro e autenticação de usuários</li>
<li>Criptografia de senhas com Bcrypt</li>
<li>Autorização de acesso baseado em roles</li>
<li>Mensagem de acesso negado personalizada</li>
<h1>Tecnologias</h1>
<li>Spring Boot 3.0 </li>
<li>Spring Security </li>
<li>JSON Web Tokens (JWT) </li>
<li>BCrypt </li>
<li>Maven </li>
<h1>Execução</h1>
Você precisará do seguinte para executar em sua máquina:
<li> Java e JDK 17+ </li>
<li> Maven 3+ </li>
Siga os seguintes passos:
<li> Clone o repositório </li>
<li> Abra o projeto e modifique src/main/resources/application.yml de acordo com sua base de dados para que a conexão seja executada</li>
<li> Execute o projeto. Caso prefira, instale e execute pelo prompt de comando com os seguintes comandos: /mvnw clean install e /mvnw spring-boot:run </li>
<li> Os endpoints para uso estão documentados no projeto</li>
<h1>Referência:</h1>
Utilizei como base de estudo e aplicação o seguinte vídeo e repositório: https://www.youtube.com/watch?v=BVdQ3iuovg0&t=468s e https://github.com/ali-bouali/spring-boot-3-jwt-security
