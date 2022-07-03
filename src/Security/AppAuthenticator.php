<?php

namespace App\Security;

use App\Entity\User;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Doctrine\ORM\EntityManagerInterface;

class AppAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    private UrlGeneratorInterface $urlGenerator;

    /**
     * @var EntityManagerInterface
     */
    private $userManager;
    /**
     * @var UserPasswordHasherInterface
     */
    private $hasher;

    public function __construct(UrlGeneratorInterface $urlGenerator, EntityManagerInterface $userManager, UserPasswordHasherInterface $passwordHasher)
    {
        $this->urlGenerator = $urlGenerator;
        $this->userManager = $userManager;
        $this->hasher = $passwordHasher;
    }

    public function authenticate(Request $request): Passport
    {
        $username = $request->request->get('username', '');

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        $user = $this->userManager->getRepository(User::class)->findOneBy(['username'=>$request->request->get('username')]);

        // Ajoute 1 au nombre d'essais ratés si l'utilisateur entre le mauvais mot de passe

            $form = [
                "username" => $request->request->get('username'),
                "password" => $request->request->get('password')
            ];

            if (!$this->hasher->isPasswordValid($user, $form['password'])) {
                $user->setFailedTries($user->getFailedTries() + 1);
                $this->userManager->persist($user);
                $this->userManager->flush();
            }

        //

        return new Passport(
            new UserBadge($username),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
            ]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }


        return new RedirectResponse($this->urlGenerator->generate('login'));
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
