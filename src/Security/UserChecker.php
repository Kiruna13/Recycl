<?php

namespace App\Security;

use App\Entity\User as User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;


class UserChecker implements UserCheckerInterface
{
    /**
     * @var EntityManagerInterface
     */
    private $userManager;

    public function __construct(EntityManagerInterface $userManager){
        $this->userManager = $userManager;
    }

    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            return;
        }

        if ($user->getFailedTries() == 3) {
            $user->setBlocked(true);
            $this->userManager->persist($user);
            $this->userManager->flush();
        }

        if ($user->isBlocked()) {
            // the message passed to this exception is meant to be displayed to the user
            throw new CustomUserMessageAccountStatusException("Votre compte est bloqué car vous avez effectué 3 tentatives de connexion incorrectes. Veuillez contacter un administrateur pour plus d'informations.");
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            return;
        }
    }
}