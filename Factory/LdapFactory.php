<?php

namespace IMAG\LdapBundle\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory,
    Symfony\Component\DependencyInjection\ContainerBuilder,
    Symfony\Component\Config\Definition\Builder\NodeDefinition,
    Symfony\Component\DependencyInjection\DefinitionDecorator,
    Symfony\Component\DependencyInjection\Reference;

class LdapFactory extends AbstractFactory
{
    public function __construct()
    {
        // Null options shall be replaced by sensible defaults in the LdapListener
        $this->addOption('username_parameter', null);
        $this->addOption('password_parameter', null);
        $this->addOption('csrf_parameter', null);
        $this->addOption('intention', null);
        $this->addOption('csrf_token_id', null);
        $this->addOption('post_only', null);
    }

    public function getPosition()
    {
        return 'form';
    }

    public function getKey()
    {
        return 'imag-ldap';
    }

    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);

        // CSRF
        //   Symfony 3.x: 'csrf_provider' replaced by 'csrf_token_generator'
        //    <-> https://github.com/symfony/symfony/blob/master/UPGRADE-3.0.md#form
        //   Backward-compatibility: keep both options (until Symfony 2.x is EOL)
        $node
            ->children()
                ->scalarNode('csrf_provider')->cannotBeEmpty()->end()
                ->scalarNode('csrf_token_generator')->cannotBeEmpty()->end()
            ->end()
            ;
    }

    protected function getListenerId()
    {
        return 'imag_ldap.security.authentication.listener';
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $dao = 'security.authentication.provider.dao.'.$id;
        $container
            ->setDefinition($dao, new DefinitionDecorator('security.authentication.provider.dao'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(2, $id)
        ;

        $provider = 'imag_ldap.security.authentication.provider.'.$id;
        $container
            ->setDefinition($provider, new DefinitionDecorator('imag_ldap.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(1, new Reference($dao))
            ->replaceArgument(4, $id)
            ;

        return $provider;
    }

    protected function createlistener($container, $id, $config, $userProvider)
    {
        $listenerId = parent::createListener($container, $id, $config, $userProvider);

        // CSRF
        //   Symfony 3.x: 'csrf_provider' replaced by 'csrf_token_generator'
        //    <-> https://github.com/symfony/symfony/blob/master/UPGRADE-3.0.md#form
        //   Backward-compatibility: keep both options (until Symfony 2.x is EOL)
        $csrfTokenGenerator = null;
        if (isset($config['csrf_provider'])) {
            $csrfTokenGenerator = $config['csrf_provider'];
            @trigger_error('"csrf_provider" option is deprecated (>=2.4); please use "csrf_token_generator" instead', E_USER_DEPRECATED);
        }
        if (isset($config['csrf_token_generator'])) {
            $csrfTokenGenerator = $config['csrf_token_generator'];
        }
        if($csrfTokenGenerator == 'form.csrf_provider') {
            @trigger_error('"form.csrf_provider" is deprecated (>=2.4); USING "security.csrf.token_manager" INSTEAD', E_USER_DEPRECATED);
            $csrfTokenGenerator = 'security.csrf.token_manager';
        }

        if (!is_null($csrfTokenGenerator)) {
            $container
                ->getDefinition($listenerId)
                ->addArgument(new Reference($csrfTokenGenerator))
                ;
        }

        return $listenerId;
    }

    protected function createEntryPoint($container, $id, $config, $defaultEntryPoint)
    {
        $entryPointId = 'imag_ldap.security.authentication.form_entry_point.'.$id;
        $container
            ->setDefinition($entryPointId, new DefinitionDecorator('imag_ldap.security.authentication.form_entry_point'))
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument($config['login_path'])
            ->addArgument($config['use_forward'])
            ;

        return $entryPointId;
    }
}
