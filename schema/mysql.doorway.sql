
/*Table structure for table `groups` */
DROP TABLE IF EXISTS `groups`;

CREATE TABLE `groups` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `description` varchar(256) DEFAULT NULL,
  `created_on` timestamp NULL DEFAULT NULL,
  `modified_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

/*Table structure for table `members` */
DROP TABLE IF EXISTS `members`;

CREATE TABLE `members` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `description` varchar(256) DEFAULT NULL,
  `created_on` timestamp NULL DEFAULT NULL,
  `modified_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COMMENT='authorized users';

/*Table structure for table `memberships` */
DROP TABLE IF EXISTS `memberships`;

CREATE TABLE `memberships` (
  `member_id` int(10) NOT NULL,
  `group_id` int(10) NOT NULL,
  UNIQUE KEY `unique` (`member_id`,`group_id`),
  KEY `FK__groups` (`group_id`),
  CONSTRAINT `FK__groups` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  CONSTRAINT `FK__members` FOREIGN KEY (`member_id`) REFERENCES `members` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Table structure for table `permissions` */
DROP TABLE IF EXISTS `permissions`;

CREATE TABLE `permissions` (
  `member_id` int(10) DEFAULT NULL,
  `group_id` int(10) DEFAULT NULL,
  `resource` varchar(64) NOT NULL,
  `action` enum('create','read','update','delete') NOT NULL,
  `created_on` timestamp NULL DEFAULT NULL,
  `modified_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

