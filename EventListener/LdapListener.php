<?php

namespace IMAG\LdapBundle\EventListener;

use Symfony\Component\EventDispatcher\EventDispatcherInterface,
    Symfony\Component\HttpFoundation\Request,
    Psr\Log\LoggerInterface,
    Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface,
    Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken,
    Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface,
    Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException,
    Symfony\Component\Security\Core\Security,
    Symfony\Component\Security\Csrf\CsrfToken,
    Symfony\Component\Security\Csrf\CsrfTokenManagerInterface,
    Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface,
    Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface,
    Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener,
    Symfony\Component\Security\Http\HttpUtils,
    Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface
;

class LdapListener extends AbstractAuthenticationListener
{
    public function __construct(TokenStorageInterface $tokenStorage,
                                AuthenticationManagerInterface $authenticationManager,
                                SessionAuthenticationStrategyInterface $sessionStrategy,
                                HttpUtils $httpUtils,
                                $providerKey,
                                AuthenticationSuccessHandlerInterface $successHandler = null,
                                AuthenticationFailureHandlerInterface $failureHandler = null,
                                array $options = array(),
                                LoggerInterface $logger = null,
                                EventDispatcherInterface $dispatcher = null,
                                CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        // CSRF
        //   Symfony 3.x: 'intention' replaced by 'csrf_token_id'
        //    <-> https://github.com/symfony/symfony/blob/master/UPGRADE-3.0.md#form
        //   Backward-compatibility: keep both options (until Symfony 2.x is EOL)
        if(is_null($options['csrf_token_id'])) {
            $options['csrf_token_id'] = $options['intention'];
        }
        if(isset($options['intention'])) {
            @trigger_error('(CSRF) "intention" option is deprecated (>=2.4); please use "csrf_token_id" instead', E_USER_DEPRECATED);
            unset($options['intention']);
        }

        // Options (override defaults)
        $options = array_merge(
            array(
                'username_parameter' => '_username',
                'password_parameter' => '_password',
                'csrf_parameter'     => '_csrf_token',
                'csrf_token_id'      => 'authenticate',
                'post_only'          => true,
            ),
            array_filter($options, function($v) {return !is_null($v);})
        );

        parent::__construct(
            $tokenStorage,
            $authenticationManager,
            $sessionStrategy,
            $httpUtils,
            $providerKey,
            $successHandler,
            $failureHandler,
            $options,
            $logger,
            $dispatcher
        );

        $this->csrfTokenManager = $csrfTokenManager;
    }

    /**
     * {@inheritdoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('post')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }

    public function attemptAuthentication(Request $request)
    {
        if ($this->options['post_only'] && 'post' !== strtolower($request->getMethod())) {
            if (null !== $this->logger) {
                $this->logger->debug(sprintf('Authentication method not supported: %s.', $request->getMethod()));
            }

            return null;
        }

        if (null !== $this->csrfTokenManager) {
            $csrfToken = new CsrfToken(
                $this->options['csrf_token_id'],
                $request->get($this->options['csrf_parameter'], null, true)
            );

            if (false === $this->csrfTokenManager->isTokenValid($csrfToken)) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        $username = trim($request->get($this->options['username_parameter'], null, true));
        $password = $request->get($this->options['password_parameter'], null, true);

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->providerKey));
    }
}
