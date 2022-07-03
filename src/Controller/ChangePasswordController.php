<?php

namespace App\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class ChangePasswordController extends AbstractController
{
    /**
     * @Route("/change/password", name="app_change_password")
     */
    public function index(Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $userManager): Response
    {
        if ($request->isMethod("POST")) {
            $newPassword = $request->request->get('newPassword');
            $newPasswordConfirmation = $request->request->get('newPasswordConfirmation');
            if ($newPassword != null && $newPassword == $newPasswordConfirmation) {
                $user = $this->getUser();
                $hashedPassword = $passwordHasher->hashPassword(
                    $user,
                    $newPassword
                );
                $date = new \DateTime('@'.strtotime('now'));
                $user->setPassword($hashedPassword);
                $user->setLastPasswordChange($date);
                $userManager->persist($user);
                $userManager->flush();
                return $this->redirectToRoute('login');
            }
        }



        return $this->render('change_password/index.html.twig', [
            'controller_name' => 'ChangePasswordController',
        ]);
    }
}
