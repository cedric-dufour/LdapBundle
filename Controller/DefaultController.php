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

use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use Symfony\Component\Security\Core\Security;

class DefaultController extends Controller
{
    public function loginAction(Request $request)
    {
        $error = $this->getAuthenticationError($request);

        return $this->render('IMAGLdapBundle:Default:login.html.twig', array(
            'last_username' => $request->getSession()->get(Security::LAST_USERNAME),
            'error'         => $error,
        ));
    }

    protected function getAuthenticationError(Request $request)
    {
        if ($request->attributes->has(Security::AUTHENTICATION_ERROR)) {
            return $request->attributes->get(Security::AUTHENTICATION_ERROR);
        }

        return $request->getSession()->get(Security::AUTHENTICATION_ERROR);
    }
}
