<?php
/*
 * This file is part of the Symfony framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace IMAG\LdapBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use Symfony\Component\Security\Core\Security;

class DefaultController extends Controller
{
    public function loginAction()
    {
        $error = $this->getAuthenticationError();

        return $this->render('IMAGLdapBundle:Default:login.html.twig', array(
            'last_username' => $this->get('request')->getSession()->get(Security::LAST_USERNAME),
            'error'         => $error,
        ));
    }

    protected function getAuthenticationError()
    {
        if ($this->get('request')->attributes->has(Security::AUTHENTICATION_ERROR)) {
            return $this->get('request')->attributes->get(Security::AUTHENTICATION_ERROR);
        }

        return $this->get('request')->getSession()->get(Security::AUTHENTICATION_ERROR);
    }
}
