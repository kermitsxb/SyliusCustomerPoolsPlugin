<?php

declare(strict_types=1);

namespace Tavy315\SyliusCustomerPoolsPlugin\Security;

use Sylius\Behat\Service\Setter\ChannelContextSetterInterface;
use Sylius\Component\Channel\Context\ChannelContextInterface;
use Sylius\Component\Channel\Repository\ChannelRepositoryInterface;
use Sylius\Component\Core\Model\ShopUserInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use Tavy315\SyliusCustomerPoolsPlugin\Model\Customer\CustomerPoolAwareInterface;
use Tavy315\SyliusCustomerPoolsPlugin\Model\CustomerPoolInterface;

final class UserChecker implements UserCheckerInterface
{
    public function __construct(
        private ChannelContextInterface $channelContext,
        private ChannelRepositoryInterface $channelRepository,
        private UserCheckerInterface $userChecker,
        private TranslatorInterface $translator,
    ) {
    }

    public function checkPreAuth(UserInterface $user): void
    {
        $this->userChecker->checkPreAuth($user);

        if (!$user instanceof ShopUserInterface) {
            return;
        }

        $customer = $user->getCustomer();
        if (!$customer instanceof CustomerPoolAwareInterface) {
            return;
        }

        $channel = $this->channelContext->getChannel();
        if (!$channel instanceof CustomerPoolAwareInterface) {
            return;
        }

        $channelCustomerPool = $channel->getCustomerPool();
        if ($channelCustomerPool === null) {
            return;
        }

        $customerPool = $customer->getCustomerPool();
        if ($customerPool === null) {
            return;
        }

        if ($channelCustomerPool->getCode() !== $customerPool->getCode()) {
            $channels = $this->channelRepository->findAll();

            foreach ($channels as $channel) {
                if ($channel instanceof CustomerPoolAwareInterface) {
                    $customerPoolTmpChannel = $channel->getCustomerPool();
                    if ($customerPoolTmpChannel instanceof CustomerPoolInterface && $channel->getCustomerPool()->getCode() === $customer->getCustomerPool()->getCode()) {
                        throw new CustomUserMessageAuthenticationException(
                            $this->translator->trans('tavy315_sylius_customer_pools.checker.wrong_channel'),
                            [ 'channel_hostname' => !empty($channel->getHostname()) ? $channel->getHostname() : $channel->getName() ]
                        );
                    }
                }
            }

            throw new CustomUserMessageAuthenticationException(
                $this->translator->trans('tavy315_sylius_customer_pools.checker.not_found'),
            );
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
        $this->userChecker->checkPostAuth($user);
    }
}
