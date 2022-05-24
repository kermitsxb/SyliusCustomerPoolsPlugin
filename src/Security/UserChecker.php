<?php

declare(strict_types=1);

namespace Tavy315\SyliusCustomerPoolsPlugin\Security;

use Sylius\Behat\Service\Setter\ChannelContextSetterInterface;
use Sylius\Component\Channel\Context\ChannelContextInterface;
use Sylius\Component\Channel\Repository\ChannelRepositoryInterface;
use Sylius\Component\Core\Model\ShopUserInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Tavy315\SyliusCustomerPoolsPlugin\Model\Customer\CustomerPoolAwareInterface;

final class UserChecker implements UserCheckerInterface
{
    private ChannelContextInterface $channelContext;

    private ChannelRepositoryInterface $channelRepository;

    private UserCheckerInterface $userChecker;

    private ChannelContextSetterInterface $channelContextSetter;

    public function __construct(
        ChannelContextInterface $channelContext,
        ChannelRepositoryInterface $channelRepository,
        UserCheckerInterface $userChecker,
        ChannelContextSetterInterface $channelContextSetter,
    )
    {
        $this->channelContext = $channelContext;
        $this->channelRepository = $channelRepository;
        $this->userChecker = $userChecker;
        $this->channelContextSetter = $channelContextSetter;
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
            $customerChannel = $this->channelRepository->findOneByCode($customerPool->getCode());
            if ($customerChannel === null) {
                return;
            } else {
                if (\empty($customerChannel->getHostname())) {
                    $this->channelContextSetter->setChannel($customerChannel);
                } else {
                    throw new CustomUserMessageAuthenticationException('You need to login on channel_hostname.', [ 'channel_hostname' => $customerChannel->getHostname() ]);
                }
            }
        }
    }

    public function checkPostAuth(UserInterface $user): void
    {
        $this->userChecker->checkPostAuth($user);
    }
}
