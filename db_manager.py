import sqlite3
import os
import threading
import hashlib
import time
import json
import random
import string
import aiohttp
import io
import base64
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
from typing import List, Tuple, Dict, Optional, Any
from loguru import logger

class DBManager:
    """SQLite数据库管理，持久化存储Cookie和关键字"""
    
    def __init__(self, db_path: str = None):
        """初始化数据库连接和表结构"""
        # 支持环境变量配置数据库路径
        if db_path is None:
            db_path = os.getenv('DB_PATH', 'data/xianyu_data.db')

        # 确保数据目录存在并有正确权限
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, mode=0o755, exist_ok=True)
                logger.info(f"创建数据目录: {db_dir}")
            except PermissionError as e:
                logger.error(f"创建数据目录失败，权限不足: {e}")
                # 尝试使用当前目录
                db_path = os.path.basename(db_path)
                logger.warning(f"使用当前目录作为数据库路径: {db_path}")
            except Exception as e:
                logger.error(f"创建数据目录失败: {e}")
                raise

        # 检查目录权限
        if db_dir and os.path.exists(db_dir):
            if not os.access(db_dir, os.W_OK):
                logger.error(f"数据目录没有写权限: {db_dir}")
                # 尝试使用当前目录
                db_path = os.path.basename(db_path)
                logger.warning(f"使用当前目录作为数据库路径: {db_path}")

        self.db_path = db_path
        logger.info(f"数据库路径: {self.db_path}")
        self.conn = None
        self.lock = threading.RLock()  # 使用可重入锁保护数据库操作

        # SQL日志配置 - 默认启用
        self.sql_log_enabled = True  # 默认启用SQL日志
        self.sql_log_level = 'INFO'  # 默认使用INFO级别

        # 允许通过环境变量覆盖默认设置
        if os.getenv('SQL_LOG_ENABLED'):
            self.sql_log_enabled = os.getenv('SQL_LOG_ENABLED', 'true').lower() == 'true'
        if os.getenv('SQL_LOG_LEVEL'):
            self.sql_log_level = os.getenv('SQL_LOG_LEVEL', 'INFO').upper()

        logger.info(f"SQL日志已启用，日志级别: {self.sql_log_level}")

        self.init_db()
    
    def init_db(self):
        """初始化数据库表结构"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            # 创建用户表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 创建邮箱验证码表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 创建图形验证码表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS captcha_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 创建cookies表（添加user_id字段和auto_confirm字段）
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cookies (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                auto_confirm INTEGER DEFAULT 1,
                remark TEXT DEFAULT '',
                pause_duration INTEGER DEFAULT 10,
                username TEXT DEFAULT '',
                password TEXT DEFAULT '',
                show_browser INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            ''')

            
            # 创建keywords表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS keywords (
                cookie_id TEXT,
                keyword TEXT,
                reply TEXT,
                item_id TEXT,
                type TEXT DEFAULT 'text',
                image_url TEXT,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 创建cookie_status表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cookie_status (
                cookie_id TEXT PRIMARY KEY,
                enabled BOOLEAN DEFAULT TRUE,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 创建AI回复配置表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_reply_settings (
                cookie_id TEXT PRIMARY KEY,
                ai_enabled BOOLEAN DEFAULT FALSE,
                model_name TEXT DEFAULT 'qwen-plus',
                api_key TEXT,
                base_url TEXT DEFAULT 'https://dashscope.aliyuncs.com/compatible-mode/v1',
                max_discount_percent INTEGER DEFAULT 10,
                max_discount_amount INTEGER DEFAULT 100,
                max_bargain_rounds INTEGER DEFAULT 3,
                custom_prompts TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 创建AI对话历史表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT NOT NULL,
                chat_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                intent TEXT,
                bargain_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies (id) ON DELETE CASCADE
            )
            ''')

            # 创建AI商品信息缓存表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_item_cache (
                item_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                price REAL,
                description TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 创建卡券表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('api', 'yifan_api', 'text', 'data', 'image')),
                api_config TEXT,
                text_content TEXT,
                data_content TEXT,
                image_url TEXT,
                description TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                delay_seconds INTEGER DEFAULT 0,
                is_multi_spec BOOLEAN DEFAULT FALSE,
                spec_name TEXT,
                spec_value TEXT,
                spec_name_2 TEXT,
                spec_value_2 TEXT,
                user_id INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')

            # 创建订单表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                item_id TEXT,
                buyer_id TEXT,
                sid TEXT,
                spec_name TEXT,
                spec_value TEXT,
                spec_name_2 TEXT,
                spec_value_2 TEXT,
                quantity TEXT,
                amount TEXT,
                order_status TEXT DEFAULT 'unknown',
                cookie_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')
            
            # 检查并添加 sid 列到 orders 表（用于简化消息查找订单）
            try:
                self._execute_sql(cursor, "SELECT sid FROM orders LIMIT 1")
            except sqlite3.OperationalError:
                # sid 列不存在，需要添加
                logger.info("正在为 orders 表添加 sid 列...")
                self._execute_sql(cursor, "ALTER TABLE orders ADD COLUMN sid TEXT")
                self._execute_sql(cursor, "CREATE INDEX IF NOT EXISTS idx_orders_sid ON orders(sid)")
                logger.info("orders 表 sid 列添加完成")

            # 检查并添加 buyer_nick 列到 orders 表（用于存储买家昵称）
            try:
                self._execute_sql(cursor, "SELECT buyer_nick FROM orders LIMIT 1")
            except sqlite3.OperationalError:
                # buyer_nick 列不存在，需要添加
                logger.info("正在为 orders 表添加 buyer_nick 列...")
                self._execute_sql(cursor, "ALTER TABLE orders ADD COLUMN buyer_nick TEXT")
                logger.info("orders 表 buyer_nick 列添加完成")

            # 检查并添加 user_id 列（用于数据库迁移）
            try:
                self._execute_sql(cursor, "SELECT user_id FROM cards LIMIT 1")
            except sqlite3.OperationalError:
                # user_id 列不存在，需要添加
                logger.info("正在为 cards 表添加 user_id 列...")
                self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1")
                self._execute_sql(cursor, "CREATE INDEX IF NOT EXISTS idx_cards_user_id ON cards(user_id)")
                logger.info("cards 表 user_id 列添加完成")

            # 检查并添加 delay_seconds 列（用于自动发货延时功能）
            try:
                self._execute_sql(cursor, "SELECT delay_seconds FROM cards LIMIT 1")
            except sqlite3.OperationalError:
                # delay_seconds 列不存在，需要添加
                logger.info("正在为 cards 表添加 delay_seconds 列...")
                self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN delay_seconds INTEGER DEFAULT 0")
                logger.info("cards 表 delay_seconds 列添加完成")

            # 检查并添加 item_id 列（用于自动回复商品ID功能）
            try:
                self._execute_sql(cursor, "SELECT item_id FROM keywords LIMIT 1")
            except sqlite3.OperationalError:
                # item_id 列不存在，需要添加
                logger.info("正在为 keywords 表添加 item_id 列...")
                self._execute_sql(cursor, "ALTER TABLE keywords ADD COLUMN item_id TEXT")
                logger.info("keywords 表 item_id 列添加完成")

            # 创建商品信息表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS item_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                item_title TEXT,
                item_description TEXT,
                item_category TEXT,
                item_price TEXT,
                item_detail TEXT,
                is_multi_spec BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE,
                UNIQUE(cookie_id, item_id)
            )
            ''')

            # 检查并添加 multi_quantity_delivery 列（用于多数量发货功能）
            try:
                self._execute_sql(cursor, "SELECT multi_quantity_delivery FROM item_info LIMIT 1")
            except sqlite3.OperationalError:
                # multi_quantity_delivery 列不存在，需要添加
                logger.info("正在为 item_info 表添加 multi_quantity_delivery 列...")
                self._execute_sql(cursor, "ALTER TABLE item_info ADD COLUMN multi_quantity_delivery BOOLEAN DEFAULT FALSE")
                logger.info("item_info 表 multi_quantity_delivery 列添加完成")

            # 创建自动发货规则表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS delivery_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword TEXT NOT NULL,
                card_id INTEGER NOT NULL,
                delivery_count INTEGER DEFAULT 1,
                enabled BOOLEAN DEFAULT TRUE,
                description TEXT,
                delivery_times INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE
            )
            ''')

            # 创建默认回复表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS default_replies (
                cookie_id TEXT PRIMARY KEY,
                enabled BOOLEAN DEFAULT FALSE,
                reply_content TEXT,
                reply_once BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 添加 reply_once 字段（如果不存在）
            try:
                cursor.execute('ALTER TABLE default_replies ADD COLUMN reply_once BOOLEAN DEFAULT FALSE')
                self.conn.commit()
                logger.info("已添加 reply_once 字段到 default_replies 表")
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e).lower():
                    logger.warning(f"添加 reply_once 字段失败: {e}")

            # 创建指定商品回复表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS item_replay (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id TEXT NOT NULL,
                    cookie_id TEXT NOT NULL,
                    reply_content TEXT NOT NULL ,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 创建默认回复记录表（记录已回复的chat_id）
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS default_reply_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT NOT NULL,
                chat_id TEXT NOT NULL,
                replied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(cookie_id, chat_id),
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 创建通知渠道表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('qq','ding_talk','dingtalk','feishu','lark','bark','email','webhook','wechat','telegram')),
                config TEXT NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 创建系统设置表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 创建消息通知配置表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS message_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT NOT NULL,
                channel_id INTEGER NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE,
                FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE,
                UNIQUE(cookie_id, channel_id)
            )
            ''')

            # 创建用户设置表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, key)
            )
            ''')

            # 创建好评模板表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS comment_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT NOT NULL,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                is_active BOOLEAN DEFAULT FALSE,
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 创建风控日志表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_control_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cookie_id TEXT NOT NULL,
                event_type TEXT NOT NULL DEFAULT 'slider_captcha',
                event_description TEXT,
                processing_result TEXT,
                processing_status TEXT DEFAULT 'processing',
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 创建通知模板表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL UNIQUE CHECK (type IN ('message', 'token_refresh', 'delivery', 'slider_success', 'face_verify', 'password_login_success', 'cookie_refresh_success')),
                template TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 插入默认通知模板
            cursor.execute('''
            INSERT OR IGNORE INTO notification_templates (type, template) VALUES
            ('message', '🚨 接收消息通知

账号: {account_id}
买家: {buyer_name} (ID: {buyer_id})
商品ID: {item_id}
聊天ID: {chat_id}
消息内容: {message}

时间: {time}'),
            ('token_refresh', 'Token刷新异常

账号ID: {account_id}
异常时间: {time}
异常信息: {error_message}

请检查账号Cookie是否过期，如有需要请及时更新Cookie配置。'),
            ('delivery', '🚨 自动发货通知

账号: {account_id}
买家: {buyer_name} (ID: {buyer_id})
商品ID: {item_id}
聊天ID: {chat_id}
结果: {result}
时间: {time}

请及时处理！'),
            ('slider_success', '✅ 滑块验证成功，cookies已自动更新到数据库

账号: {account_id}
时间: {time}'),
            ('face_verify', '⚠️ 账号密码登录需要人脸验证

账号: {account_id}
时间: {time}

请点击验证链接完成验证:
{verification_url}

在验证期间，闲鱼自动回复暂时无法使用。'),
            ('password_login_success', '✅ 密码登录成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号Cookie已更新，正在重启服务...'),
            ('cookie_refresh_success', '✅ 刷新Cookie成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号已可正常使用。')
            ''')

            # 插入默认系统设置（不包括管理员密码，由reply_server.py初始化）
            cursor.execute('''
            INSERT OR IGNORE INTO system_settings (key, value, description) VALUES
            ('theme_color', 'blue', '主题颜色'),
            ('registration_enabled', 'true', '是否开启用户注册'),
            ('show_default_login_info', 'true', '是否显示默认登录信息'),
            ('login_captcha_enabled', 'true', '是否开启登录验证码'),
            ('smtp_server', '', 'SMTP服务器地址'),
            ('smtp_port', '587', 'SMTP端口'),
            ('smtp_user', '', 'SMTP登录用户名（发件邮箱）'),
            ('smtp_password', '', 'SMTP登录密码/授权码'),
            ('smtp_from', '', '发件人显示名（留空则使用用户名）'),
            ('smtp_use_tls', 'true', '是否启用TLS'),
            ('smtp_use_ssl', 'false', '是否启用SSL'),
            ('qq_reply_secret_key', 'xianyu_qq_reply_2024', 'QQ回复消息API秘钥')
            ''')

            # 检查并升级数据库
            self.check_and_upgrade_db(cursor)

            # 执行数据库迁移
            self._migrate_database(cursor)

            self.conn.commit()
            logger.info("数据库初始化完成")
        except Exception as e:
            logger.error(f"数据库初始化失败: {e}")
            self.conn.rollback()
            raise

    def _migrate_database(self, cursor):
        """执行数据库迁移"""
        try:
            # 检查cards表是否存在image_url列
            cursor.execute("PRAGMA table_info(cards)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'image_url' not in columns:
                logger.info("添加cards表的image_url列...")
                cursor.execute("ALTER TABLE cards ADD COLUMN image_url TEXT")
                logger.info("数据库迁移完成：添加image_url列")

            # 检查并更新CHECK约束（重建表以支持image类型）
            self._update_cards_table_constraints(cursor)

            # 检查cookies表是否存在remark列
            cursor.execute("PRAGMA table_info(cookies)")
            cookie_columns = [column[1] for column in cursor.fetchall()]

            if 'remark' not in cookie_columns:
                logger.info("添加cookies表的remark列...")
                cursor.execute("ALTER TABLE cookies ADD COLUMN remark TEXT DEFAULT ''")
                logger.info("数据库迁移完成：添加remark列")

            # 检查cookies表是否存在pause_duration列
            if 'pause_duration' not in cookie_columns:
                logger.info("添加cookies表的pause_duration列...")
                cursor.execute("ALTER TABLE cookies ADD COLUMN pause_duration INTEGER DEFAULT 10")
                logger.info("数据库迁移完成：添加pause_duration列")

            # 检查cookies表是否存在auto_comment列
            if 'auto_comment' not in cookie_columns:
                logger.info("添加cookies表的auto_comment列...")
                cursor.execute("ALTER TABLE cookies ADD COLUMN auto_comment INTEGER DEFAULT 0")
                logger.info("数据库迁移完成：添加auto_comment列")

            # 迁移notification_templates表以支持新的模板类型
            self._migrate_notification_templates(cursor)

        except Exception as e:
            logger.error(f"数据库迁移失败: {e}")
            # 迁移失败不应该阻止程序启动
            pass

    def _update_cards_table_constraints(self, cursor):
        """更新cards表的CHECK约束以支持image和yifan_api类型"""
        try:
            # 尝试插入一个测试的yifan_api类型记录来检查约束
            cursor.execute('''
                INSERT INTO cards (name, type, user_id)
                VALUES ('__test_yifan_constraint__', 'yifan_api', 1)
            ''')
            # 如果插入成功，立即删除测试记录
            cursor.execute("DELETE FROM cards WHERE name = '__test_yifan_constraint__'")
            logger.info("cards表约束检查通过，支持yifan_api类型")
        except Exception as e:
            if "CHECK constraint failed" in str(e) or "constraint" in str(e).lower():
                logger.info("检测到旧的CHECK约束，开始更新cards表以支持yifan_api类型...")

                # 重建表以更新约束
                try:
                    # 1. 创建新表
                    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cards_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL CHECK (type IN ('api', 'yifan_api', 'text', 'data', 'image')),
                        api_config TEXT,
                        text_content TEXT,
                        data_content TEXT,
                        image_url TEXT,
                        description TEXT,
                        enabled BOOLEAN DEFAULT TRUE,
                        delay_seconds INTEGER DEFAULT 0,
                        is_multi_spec BOOLEAN DEFAULT FALSE,
                        spec_name TEXT,
                        spec_value TEXT,
                        spec_name_2 TEXT,
                        spec_value_2 TEXT,
                        user_id INTEGER NOT NULL DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                    ''')

                    # 2. 复制数据（双规格字段设为NULL，由后续迁移填充）
                    cursor.execute('''
                    INSERT INTO cards_new (id, name, type, api_config, text_content, data_content, image_url,
                                          description, enabled, delay_seconds, is_multi_spec, spec_name, spec_value,
                                          spec_name_2, spec_value_2, user_id, created_at, updated_at)
                    SELECT id, name, type, api_config, text_content, data_content, image_url,
                           description, enabled, delay_seconds, is_multi_spec, spec_name, spec_value,
                           NULL, NULL, user_id, created_at, updated_at
                    FROM cards
                    ''')

                    # 3. 删除旧表
                    cursor.execute("DROP TABLE cards")

                    # 4. 重命名新表
                    cursor.execute("ALTER TABLE cards_new RENAME TO cards")

                    logger.info("cards表约束更新完成，现在支持image类型")

                except Exception as rebuild_error:
                    logger.error(f"重建cards表失败: {rebuild_error}")
                    # 如果重建失败，尝试回滚
                    try:
                        cursor.execute("DROP TABLE IF EXISTS cards_new")
                    except:
                        pass
            else:
                logger.error(f"检查cards表约束时出现未知错误: {e}")

    def _migrate_notification_templates(self, cursor):
        """迁移notification_templates表以支持新的模板类型"""
        try:
            # 检查是否已存在cookie_refresh_success模板
            cursor.execute("SELECT COUNT(*) FROM notification_templates WHERE type = 'cookie_refresh_success'")
            if cursor.fetchone()[0] == 0:
                logger.info("添加Cookie刷新成功通知模板...")

                # 重建表以更新CHECK约束
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS notification_templates_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL UNIQUE CHECK (type IN ('message', 'token_refresh', 'delivery', 'slider_success', 'face_verify', 'password_login_success', 'cookie_refresh_success')),
                    template TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')

                # 复制现有数据
                cursor.execute('''
                INSERT OR IGNORE INTO notification_templates_new (id, type, template, created_at, updated_at)
                SELECT id, type, template, created_at, updated_at FROM notification_templates
                ''')

                # 删除旧表
                cursor.execute("DROP TABLE notification_templates")

                # 重命名新表
                cursor.execute("ALTER TABLE notification_templates_new RENAME TO notification_templates")

                # 插入新的默认模板（包括之前可能缺失的）
                cursor.execute('''
                INSERT OR IGNORE INTO notification_templates (type, template) VALUES
                ('slider_success', '✅ 滑块验证成功，cookies已自动更新到数据库

账号: {account_id}
时间: {time}'),
                ('face_verify', '⚠️ 账号密码登录需要人脸验证

账号: {account_id}
时间: {time}

请点击验证链接完成验证:
{verification_url}

在验证期间，闲鱼自动回复暂时无法使用。'),
                ('password_login_success', '✅ 密码登录成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号Cookie已更新，正在重启服务...'),
                ('cookie_refresh_success', '✅ 刷新Cookie成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号已可正常使用。')
                ''')

                logger.info("通知模板类型迁移完成")
        except Exception as e:
            logger.warning(f"迁移notification_templates表时出错（可能表不存在）: {e}")
            # 如果迁移失败，尝试清理
            try:
                cursor.execute("DROP TABLE IF EXISTS notification_templates_new")
            except:
                pass

    def check_and_upgrade_db(self, cursor):
        """检查数据库版本并执行必要的升级"""
        try:
            # 获取当前数据库版本
            current_version = self.get_system_setting("db_version") or "1.0"
            logger.info(f"当前数据库版本: {current_version}")

            if current_version == "1.0":
                logger.info("开始升级数据库到版本1.0...")
                self.update_admin_user_id(cursor)
                self.set_system_setting("db_version", "1.0", "数据库版本号")
                logger.info("数据库升级到版本1.0完成")
            
            # 如果版本低于需要升级的版本，执行升级
            if current_version < "1.1":
                logger.info("开始升级数据库到版本1.1...")
                self.upgrade_notification_channels_table(cursor)
                self.set_system_setting("db_version", "1.1", "数据库版本号")
                logger.info("数据库升级到版本1.1完成")

            # 升级到版本1.2 - 支持更多通知渠道类型
            if current_version < "1.2":
                logger.info("开始升级数据库到版本1.2...")
                self.upgrade_notification_channels_types(cursor)
                self.set_system_setting("db_version", "1.2", "数据库版本号")
                logger.info("数据库升级到版本1.2完成")

            # 升级到版本1.3 - 添加关键词类型和图片URL字段
            if current_version < "1.3":
                logger.info("开始升级数据库到版本1.3...")
                self.upgrade_keywords_table_for_image_support(cursor)
                self.set_system_setting("db_version", "1.3", "数据库版本号")
                logger.info("数据库升级到版本1.3完成")
            
            
            # 升级到版本1.4 - 添加关键词类型和图片URL字段
            if current_version < "1.4":
                logger.info("开始升级数据库到版本1.4...")
                self.upgrade_notification_channels_types(cursor)
                self.set_system_setting("db_version", "1.4", "数据库版本号")
                logger.info("数据库升级到版本1.4完成")

            # 升级到版本1.5 - 为cookies表添加账号登录字段
            if current_version < "1.5":
                logger.info("开始升级数据库到版本1.5...")
                self.upgrade_cookies_table_for_account_login(cursor)
                self.set_system_setting("db_version", "1.5", "数据库版本号")
                logger.info("数据库升级到版本1.5完成")

            # 升级到版本1.6 - 为cookies表添加代理配置字段
            if current_version < "1.6":
                logger.info("开始升级数据库到版本1.6...")
                self.upgrade_cookies_table_for_proxy(cursor)
                self.set_system_setting("db_version", "1.6", "数据库版本号")
                logger.info("数据库升级到版本1.6完成")

            # 升级到版本1.7 - 为users表添加is_admin字段
            if current_version < "1.7":
                logger.info("开始升级数据库到版本1.7...")
                self.upgrade_users_table_for_admin(cursor)
                self.set_system_setting("db_version", "1.7", "数据库版本号")
                logger.info("数据库升级到版本1.7完成")

            # 迁移遗留数据（在所有版本升级完成后执行）
            self.migrate_legacy_data(cursor)

        except Exception as e:
            logger.error(f"数据库版本检查或升级失败: {e}")
            raise
            
    def update_admin_user_id(self, cursor):
        """更新admin用户ID"""
        try:
            logger.info("开始更新admin用户ID...")
            # 创建默认admin用户（只在首次初始化时创建）
            cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
            admin_exists = cursor.fetchone()[0] > 0

            if not admin_exists:
                # 首次创建admin用户，设置默认密码和管理员权限
                default_password_hash = hashlib.sha256("admin123".encode()).hexdigest()
                # 检查is_admin列是否存在
                try:
                    cursor.execute('SELECT is_admin FROM users LIMIT 1')
                    cursor.execute('''
                    INSERT INTO users (username, email, password_hash, is_admin) VALUES
                    ('admin', 'admin@localhost', ?, 1)
                    ''', (default_password_hash,))
                except sqlite3.OperationalError:
                    # is_admin列不存在，使用旧的INSERT语句
                    cursor.execute('''
                    INSERT INTO users (username, email, password_hash) VALUES
                    ('admin', 'admin@localhost', ?)
                    ''', (default_password_hash,))
                logger.info("创建默认admin用户，密码: admin123")

            # 获取admin用户ID，用于历史数据绑定
            self._execute_sql(cursor, "SELECT id FROM users WHERE username = 'admin'")
            admin_user = cursor.fetchone()
            if admin_user:
                admin_user_id = admin_user[0]

                # 将历史cookies数据绑定到admin用户（如果user_id列不存在）
                try:
                    self._execute_sql(cursor, "SELECT user_id FROM cookies LIMIT 1")
                except sqlite3.OperationalError:
                    # user_id列不存在，需要添加并更新历史数据
                    self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN user_id INTEGER")
                    self._execute_sql(cursor, "UPDATE cookies SET user_id = ? WHERE user_id IS NULL", (admin_user_id,))
                else:
                    # user_id列存在，更新NULL值
                    self._execute_sql(cursor, "UPDATE cookies SET user_id = ? WHERE user_id IS NULL", (admin_user_id,))

                # 为cookies表添加auto_confirm字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT auto_confirm FROM cookies LIMIT 1")
                except sqlite3.OperationalError:
                    # auto_confirm列不存在，需要添加并设置默认值
                    self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN auto_confirm INTEGER DEFAULT 1")
                    self._execute_sql(cursor, "UPDATE cookies SET auto_confirm = 1 WHERE auto_confirm IS NULL")
                else:
                    # auto_confirm列存在，更新NULL值
                    self._execute_sql(cursor, "UPDATE cookies SET auto_confirm = 1 WHERE auto_confirm IS NULL")

                # 为delivery_rules表添加user_id字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT user_id FROM delivery_rules LIMIT 1")
                except sqlite3.OperationalError:
                    # user_id列不存在，需要添加并更新历史数据
                    self._execute_sql(cursor, "ALTER TABLE delivery_rules ADD COLUMN user_id INTEGER")
                    self._execute_sql(cursor, "UPDATE delivery_rules SET user_id = ? WHERE user_id IS NULL", (admin_user_id,))
                else:
                    # user_id列存在，更新NULL值
                    self._execute_sql(cursor, "UPDATE delivery_rules SET user_id = ? WHERE user_id IS NULL", (admin_user_id,))

                # 为delivery_rules表添加今日发货统计字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT last_delivery_date FROM delivery_rules LIMIT 1")
                except sqlite3.OperationalError:
                    # 今日发货字段不存在，需要添加
                    self._execute_sql(cursor, "ALTER TABLE delivery_rules ADD COLUMN last_delivery_date DATE")
                    self._execute_sql(cursor, "ALTER TABLE delivery_rules ADD COLUMN today_delivery_times INTEGER DEFAULT 0")
                    logger.info("已添加 last_delivery_date 和 today_delivery_times 字段到 delivery_rules 表")

                # 为notification_channels表添加user_id字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT user_id FROM notification_channels LIMIT 1")
                except sqlite3.OperationalError:
                    # user_id列不存在，需要添加并更新历史数据
                    self._execute_sql(cursor, "ALTER TABLE notification_channels ADD COLUMN user_id INTEGER")
                    self._execute_sql(cursor, "UPDATE notification_channels SET user_id = ? WHERE user_id IS NULL", (admin_user_id,))
                else:
                    # user_id列存在，更新NULL值
                    self._execute_sql(cursor, "UPDATE notification_channels SET user_id = ? WHERE user_id IS NULL", (admin_user_id,))

                # 为email_verifications表添加type字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT type FROM email_verifications LIMIT 1")
                except sqlite3.OperationalError:
                    # type列不存在，需要添加并更新历史数据
                    self._execute_sql(cursor, "ALTER TABLE email_verifications ADD COLUMN type TEXT DEFAULT 'register'")
                    self._execute_sql(cursor, "UPDATE email_verifications SET type = 'register' WHERE type IS NULL")
                else:
                    # type列存在，更新NULL值
                    self._execute_sql(cursor, "UPDATE email_verifications SET type = 'register' WHERE type IS NULL")

                # 为cards表添加多规格字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT is_multi_spec FROM cards LIMIT 1")
                except sqlite3.OperationalError:
                    # 多规格字段不存在，需要添加
                    self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN is_multi_spec BOOLEAN DEFAULT FALSE")
                    self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN spec_name TEXT")
                    self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN spec_value TEXT")
                    logger.info("为cards表添加多规格字段")

                # 为cards表添加双规格字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT spec_name_2 FROM cards LIMIT 1")
                except sqlite3.OperationalError:
                    # 双规格字段不存在，需要添加
                    self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN spec_name_2 TEXT")
                    self._execute_sql(cursor, "ALTER TABLE cards ADD COLUMN spec_value_2 TEXT")
                    logger.info("为cards表添加双规格字段(spec_name_2, spec_value_2)")

                # 为orders表添加双规格字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT spec_name_2 FROM orders LIMIT 1")
                except sqlite3.OperationalError:
                    # 双规格字段不存在，需要添加
                    self._execute_sql(cursor, "ALTER TABLE orders ADD COLUMN spec_name_2 TEXT")
                    self._execute_sql(cursor, "ALTER TABLE orders ADD COLUMN spec_value_2 TEXT")
                    logger.info("为orders表添加双规格字段(spec_name_2, spec_value_2)")

                # 为item_info表添加多规格字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT is_multi_spec FROM item_info LIMIT 1")
                except sqlite3.OperationalError:
                    # 多规格字段不存在，需要添加
                    self._execute_sql(cursor, "ALTER TABLE item_info ADD COLUMN is_multi_spec BOOLEAN DEFAULT FALSE")
                    logger.info("为item_info表添加多规格字段")

                # 为item_info表添加多数量发货字段（如果不存在）
                try:
                    self._execute_sql(cursor, "SELECT multi_quantity_delivery FROM item_info LIMIT 1")
                except sqlite3.OperationalError:
                    # 多数量发货字段不存在，需要添加
                    self._execute_sql(cursor, "ALTER TABLE item_info ADD COLUMN multi_quantity_delivery BOOLEAN DEFAULT FALSE")
                    logger.info("为item_info表添加多数量发货字段")

                # 处理keywords表的唯一约束问题
                # 由于SQLite不支持直接修改约束，我们需要重建表
                self._migrate_keywords_table_constraints(cursor)

            self.conn.commit()
            logger.info(f"admin用户ID更新完成")
        except Exception as e:
            logger.error(f"更新admin用户ID失败: {e}")
            raise
            
    def upgrade_notification_channels_table(self, cursor):
        """升级notification_channels表的type字段约束"""
        try:
            logger.info("开始升级notification_channels表...")
            
            # 检查表是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notification_channels'")
            if not cursor.fetchone():
                logger.info("notification_channels表不存在，无需升级")
                return True
                
            # 检查表中是否有数据
            cursor.execute("SELECT COUNT(*) FROM notification_channels")
            count = cursor.fetchone()[0]

            # 删除可能存在的临时表
            cursor.execute("DROP TABLE IF EXISTS notification_channels_new")

            # 创建临时表
            cursor.execute('''
            CREATE TABLE notification_channels_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('qq','ding_talk')),
                config TEXT NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # 复制数据，并转换不兼容的类型
            if count > 0:
                logger.info(f"复制 {count} 条通知渠道数据到新表")
                # 先查看现有数据的类型
                cursor.execute("SELECT DISTINCT type FROM notification_channels")
                existing_types = [row[0] for row in cursor.fetchall()]
                logger.info(f"现有通知渠道类型: {existing_types}")

                # 获取所有现有数据进行逐行处理
                cursor.execute("SELECT * FROM notification_channels")
                existing_data = cursor.fetchall()

                # 逐行转移数据，确保类型映射正确
                for row in existing_data:
                    old_type = row[3] if len(row) > 3 else 'qq'  # type字段，默认为qq

                    # 类型映射规则
                    type_mapping = {
                        'dingtalk': 'ding_talk',
                        'ding_talk': 'ding_talk',
                        'qq': 'qq',
                        'email': 'qq',  # 暂时映射为qq，后续版本会支持
                        'webhook': 'qq',  # 暂时映射为qq，后续版本会支持
                        'wechat': 'qq',  # 暂时映射为qq，后续版本会支持
                        'telegram': 'qq'  # 暂时映射为qq，后续版本会支持
                    }

                    new_type = type_mapping.get(old_type, 'qq')  # 默认转换为qq类型

                    if old_type != new_type:
                        logger.info(f"转换通知渠道类型: {old_type} -> {new_type}")

                    # 插入到新表
                    cursor.execute('''
                    INSERT INTO notification_channels_new
                    (id, name, user_id, type, config, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        row[0],  # id
                        row[1],  # name
                        row[2],  # user_id
                        new_type,  # type (转换后的)
                        row[4] if len(row) > 4 else '{}',  # config
                        row[5] if len(row) > 5 else True,  # enabled
                        row[6] if len(row) > 6 else None,  # created_at
                        row[7] if len(row) > 7 else None   # updated_at
                    ))
            
            # 删除旧表
            cursor.execute("DROP TABLE notification_channels")
            
            # 重命名新表
            cursor.execute("ALTER TABLE notification_channels_new RENAME TO notification_channels")
            
            logger.info("notification_channels表升级完成")
            return True
        except Exception as e:
            logger.error(f"升级notification_channels表失败: {e}")
            raise

    def upgrade_notification_channels_types(self, cursor):
        """升级notification_channels表支持更多渠道类型"""
        try:
            logger.info("开始升级notification_channels表支持更多渠道类型...")

            # 检查表是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notification_channels'")
            if not cursor.fetchone():
                logger.info("notification_channels表不存在，无需升级")
                return True

            # 检查表中是否有数据
            cursor.execute("SELECT COUNT(*) FROM notification_channels")
            count = cursor.fetchone()[0]

            # 获取现有数据
            existing_data = []
            if count > 0:
                cursor.execute("SELECT * FROM notification_channels")
                existing_data = cursor.fetchall()
                logger.info(f"备份 {count} 条通知渠道数据")

            # 创建新表，支持所有通知渠道类型
            cursor.execute('''
            CREATE TABLE notification_channels_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('qq','ding_talk','dingtalk','feishu','lark','bark','email','webhook','wechat','telegram')),
                config TEXT NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # 复制数据，同时处理类型映射
            if existing_data:
                logger.info(f"迁移 {len(existing_data)} 条通知渠道数据到新表")
                for row in existing_data:
                    # 处理类型映射，支持更多渠道类型
                    old_type = row[3] if len(row) > 3 else 'qq'  # type字段

                    # 完整的类型映射规则，支持所有通知渠道
                    type_mapping = {
                        'ding_talk': 'dingtalk',  # 统一为dingtalk
                        'dingtalk': 'dingtalk',
                        'qq': 'qq',
                        'feishu': 'feishu',      # 飞书通知
                        'lark': 'lark',          # 飞书通知（英文名）
                        'bark': 'bark',          # Bark通知
                        'email': 'email',        # 邮件通知
                        'webhook': 'webhook',    # Webhook通知
                        'wechat': 'wechat',      # 微信通知
                        'telegram': 'telegram'   # Telegram通知
                    }

                    new_type = type_mapping.get(old_type, 'qq')  # 默认为qq

                    if old_type != new_type:
                        logger.info(f"转换通知渠道类型: {old_type} -> {new_type}")

                    # 插入到新表，确保字段完整性
                    cursor.execute('''
                    INSERT INTO notification_channels_new
                    (id, name, user_id, type, config, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        row[0],  # id
                        row[1],  # name
                        row[2],  # user_id
                        new_type,  # type (转换后的)
                        row[4] if len(row) > 4 else '{}',  # config
                        row[5] if len(row) > 5 else True,  # enabled
                        row[6] if len(row) > 6 else None,  # created_at
                        row[7] if len(row) > 7 else None   # updated_at
                    ))

            # 删除旧表
            cursor.execute("DROP TABLE notification_channels")

            # 重命名新表
            cursor.execute("ALTER TABLE notification_channels_new RENAME TO notification_channels")

            logger.info("notification_channels表类型升级完成")
            logger.info("✅ 现在支持以下所有通知渠道类型:")
            logger.info("   - qq (QQ通知)")
            logger.info("   - ding_talk/dingtalk (钉钉通知)")
            logger.info("   - feishu/lark (飞书通知)")
            logger.info("   - bark (Bark通知)")
            logger.info("   - email (邮件通知)")
            logger.info("   - webhook (Webhook通知)")
            logger.info("   - wechat (微信通知)")
            logger.info("   - telegram (Telegram通知)")
            return True
        except Exception as e:
            logger.error(f"升级notification_channels表类型失败: {e}")
            raise

    def upgrade_cookies_table_for_account_login(self, cursor):
        """升级cookies表支持账号密码登录功能"""
        try:
            logger.info("开始为cookies表添加账号登录相关字段...")

            # 为cookies表添加username字段（如果不存在）
            try:
                self._execute_sql(cursor, "SELECT username FROM cookies LIMIT 1")
                logger.info("cookies表username字段已存在")
            except sqlite3.OperationalError:
                # username字段不存在，需要添加
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN username TEXT DEFAULT ''")
                logger.info("为cookies表添加username字段")

            # 为cookies表添加password字段（如果不存在）
            try:
                self._execute_sql(cursor, "SELECT password FROM cookies LIMIT 1")
                logger.info("cookies表password字段已存在")
            except sqlite3.OperationalError:
                # password字段不存在，需要添加
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN password TEXT DEFAULT ''")
                logger.info("为cookies表添加password字段")

            # 为cookies表添加show_browser字段（如果不存在）
            try:
                self._execute_sql(cursor, "SELECT show_browser FROM cookies LIMIT 1")
                logger.info("cookies表show_browser字段已存在")
            except sqlite3.OperationalError:
                # show_browser字段不存在，需要添加
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN show_browser INTEGER DEFAULT 0")
                logger.info("为cookies表添加show_browser字段")

            logger.info("✅ cookies表账号登录字段升级完成")
            logger.info("   - username: 用于密码登录的用户名")
            logger.info("   - password: 用于密码登录的密码")
            logger.info("   - show_browser: 登录时是否显示浏览器（0=隐藏，1=显示）")
            return True
        except Exception as e:
            logger.error(f"升级cookies表账号登录字段失败: {e}")
            raise

    def upgrade_cookies_table_for_proxy(self, cursor):
        """升级cookies表支持代理配置功能"""
        try:
            logger.info("开始为cookies表添加代理配置相关字段...")

            # 为cookies表添加proxy_type字段（代理类型：none/http/https/socks5）
            try:
                self._execute_sql(cursor, "SELECT proxy_type FROM cookies LIMIT 1")
                logger.info("cookies表proxy_type字段已存在")
            except sqlite3.OperationalError:
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN proxy_type TEXT DEFAULT 'none'")
                logger.info("为cookies表添加proxy_type字段")

            # 为cookies表添加proxy_host字段（代理服务器地址）
            try:
                self._execute_sql(cursor, "SELECT proxy_host FROM cookies LIMIT 1")
                logger.info("cookies表proxy_host字段已存在")
            except sqlite3.OperationalError:
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN proxy_host TEXT DEFAULT ''")
                logger.info("为cookies表添加proxy_host字段")

            # 为cookies表添加proxy_port字段（代理端口）
            try:
                self._execute_sql(cursor, "SELECT proxy_port FROM cookies LIMIT 1")
                logger.info("cookies表proxy_port字段已存在")
            except sqlite3.OperationalError:
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN proxy_port INTEGER DEFAULT 0")
                logger.info("为cookies表添加proxy_port字段")

            # 为cookies表添加proxy_user字段（代理认证用户名）
            try:
                self._execute_sql(cursor, "SELECT proxy_user FROM cookies LIMIT 1")
                logger.info("cookies表proxy_user字段已存在")
            except sqlite3.OperationalError:
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN proxy_user TEXT DEFAULT ''")
                logger.info("为cookies表添加proxy_user字段")

            # 为cookies表添加proxy_pass字段（代理认证密码）
            try:
                self._execute_sql(cursor, "SELECT proxy_pass FROM cookies LIMIT 1")
                logger.info("cookies表proxy_pass字段已存在")
            except sqlite3.OperationalError:
                self._execute_sql(cursor, "ALTER TABLE cookies ADD COLUMN proxy_pass TEXT DEFAULT ''")
                logger.info("为cookies表添加proxy_pass字段")

            logger.info("✅ cookies表代理配置字段升级完成")
            logger.info("   - proxy_type: 代理类型 (none/http/https/socks5)")
            logger.info("   - proxy_host: 代理服务器地址")
            logger.info("   - proxy_port: 代理端口")
            logger.info("   - proxy_user: 代理认证用户名（可选）")
            logger.info("   - proxy_pass: 代理认证密码（可选）")
            return True
        except Exception as e:
            logger.error(f"升级cookies表代理配置字段失败: {e}")
            raise

    def upgrade_users_table_for_admin(self, cursor):
        """升级users表支持管理员权限字段"""
        try:
            logger.info("开始为users表添加管理员权限字段...")

            # 为users表添加is_admin字段（如果不存在）
            try:
                self._execute_sql(cursor, "SELECT is_admin FROM users LIMIT 1")
                logger.info("users表is_admin字段已存在")
            except sqlite3.OperationalError:
                # is_admin字段不存在，需要添加
                self._execute_sql(cursor, "ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE")
                logger.info("为users表添加is_admin字段")

            # 将admin用户设置为管理员
            self._execute_sql(cursor, "UPDATE users SET is_admin = 1 WHERE username = 'admin'")
            logger.info("已将admin用户设置为管理员")

            logger.info("✅ users表管理员权限字段升级完成")
            logger.info("   - is_admin: 是否为管理员 (0=普通用户, 1=管理员)")
            return True
        except Exception as e:
            logger.error(f"升级users表管理员权限字段失败: {e}")
            raise

    def migrate_legacy_data(self, cursor):
        """迁移遗留数据到新表结构"""
        try:
            logger.info("开始检查和迁移遗留数据...")

            # 检查是否有需要迁移的老表
            legacy_tables = [
                'old_notification_channels',
                'legacy_delivery_rules',
                'old_keywords',
                'backup_cookies'
            ]

            for table_name in legacy_tables:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
                if cursor.fetchone():
                    logger.info(f"发现遗留表: {table_name}，开始迁移数据...")
                    self._migrate_table_data(cursor, table_name)

            logger.info("遗留数据迁移完成")
            return True
        except Exception as e:
            logger.error(f"迁移遗留数据失败: {e}")
            return False

    def _migrate_table_data(self, cursor, table_name: str):
        """迁移指定表的数据"""
        try:
            if table_name == 'old_notification_channels':
                # 迁移通知渠道数据
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]

                if count > 0:
                    cursor.execute(f"SELECT * FROM {table_name}")
                    old_data = cursor.fetchall()

                    for row in old_data:
                        # 处理数据格式转换
                        cursor.execute('''
                        INSERT OR IGNORE INTO notification_channels
                        (name, user_id, type, config, enabled)
                        VALUES (?, ?, ?, ?, ?)
                        ''', (
                            row[1] if len(row) > 1 else f"迁移渠道_{row[0]}",
                            row[2] if len(row) > 2 else 1,  # 默认admin用户
                            self._normalize_channel_type(row[3] if len(row) > 3 else 'qq'),
                            row[4] if len(row) > 4 else '{}',
                            row[5] if len(row) > 5 else True
                        ))

                    logger.info(f"成功迁移 {count} 条通知渠道数据")

                    # 迁移完成后删除老表
                    cursor.execute(f"DROP TABLE {table_name}")
                    logger.info(f"已删除遗留表: {table_name}")

        except Exception as e:
            logger.error(f"迁移表 {table_name} 数据失败: {e}")

    def _normalize_channel_type(self, old_type: str) -> str:
        """标准化通知渠道类型"""
        type_mapping = {
            'ding_talk': 'dingtalk',
            'dingtalk': 'dingtalk',
            'qq': 'qq',
            'email': 'email',
            'webhook': 'webhook',
            'wechat': 'wechat',
            'telegram': 'telegram',
            # 处理一些可能的变体
            'dingding': 'dingtalk',
            'weixin': 'wechat',
            'tg': 'telegram'
        }
        return type_mapping.get(old_type.lower(), 'qq')
    
    def _migrate_keywords_table_constraints(self, cursor):
        """迁移keywords表的约束，支持基于商品ID的唯一性校验"""
        try:
            # 检查是否已经迁移过（通过检查是否存在新的唯一索引）
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_keywords_unique_with_item'")
            if cursor.fetchone():
                logger.info("keywords表约束已经迁移过，跳过")
                return

            logger.info("开始迁移keywords表约束...")

            # 1. 创建临时表，不设置主键约束
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS keywords_temp (
                cookie_id TEXT,
                keyword TEXT,
                reply TEXT,
                item_id TEXT,
                FOREIGN KEY (cookie_id) REFERENCES cookies(id) ON DELETE CASCADE
            )
            ''')

            # 2. 复制现有数据到临时表
            cursor.execute('''
            INSERT INTO keywords_temp (cookie_id, keyword, reply, item_id)
            SELECT cookie_id, keyword, reply, item_id FROM keywords
            ''')

            # 3. 删除原表
            cursor.execute('DROP TABLE keywords')

            # 4. 重命名临时表
            cursor.execute('ALTER TABLE keywords_temp RENAME TO keywords')

            # 5. 创建复合唯一索引来实现我们需要的约束逻辑
            # 对于item_id为空的情况：(cookie_id, keyword)必须唯一
            cursor.execute('''
            CREATE UNIQUE INDEX idx_keywords_unique_no_item
            ON keywords(cookie_id, keyword)
            WHERE item_id IS NULL OR item_id = ''
            ''')

            # 对于item_id不为空的情况：(cookie_id, keyword, item_id)必须唯一
            cursor.execute('''
            CREATE UNIQUE INDEX idx_keywords_unique_with_item
            ON keywords(cookie_id, keyword, item_id)
            WHERE item_id IS NOT NULL AND item_id != ''
            ''')

            logger.info("keywords表约束迁移完成")

        except Exception as e:
            logger.error(f"迁移keywords表约束失败: {e}")
            # 如果迁移失败，尝试回滚
            try:
                cursor.execute('DROP TABLE IF EXISTS keywords_temp')
            except:
                pass
            raise

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def get_connection(self):
        """获取数据库连接，如果已关闭则重新连接"""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        return self.conn

    def _log_sql(self, sql: str, params: tuple = None, operation: str = "EXECUTE"):
        """记录SQL执行日志"""
        if not self.sql_log_enabled:
            return

        # 格式化参数
        params_str = ""
        if params:
            if isinstance(params, (list, tuple)):
                if len(params) > 0:
                    # 限制参数长度，避免日志过长
                    formatted_params = []
                    for param in params:
                        if isinstance(param, str) and len(param) > 100:
                            formatted_params.append(f"{param[:100]}...")
                        else:
                            formatted_params.append(repr(param))
                    params_str = f" | 参数: [{', '.join(formatted_params)}]"

        # 格式化SQL（移除多余空白）
        formatted_sql = ' '.join(sql.split())

        # 根据配置的日志级别输出
        log_message = f"🗄️ SQL {operation}: {formatted_sql}{params_str}"

        if self.sql_log_level == 'DEBUG':
            logger.debug(log_message)
        elif self.sql_log_level == 'INFO':
            logger.info(log_message)
        elif self.sql_log_level == 'WARNING':
            logger.warning(log_message)
        else:
            logger.debug(log_message)

    def _execute_sql(self, cursor, sql: str, params: tuple = None):
        """执行SQL并记录日志"""
        self._log_sql(sql, params, "EXECUTE")
        if params:
            return cursor.execute(sql, params)
        else:
            return cursor.execute(sql)

    def _executemany_sql(self, cursor, sql: str, params_list):
        """批量执行SQL并记录日志"""
        self._log_sql(sql, f"批量执行 {len(params_list)} 条记录", "EXECUTEMANY")
        return cursor.executemany(sql, params_list)
    
    # -------------------- Cookie操作 --------------------
    def save_cookie(self, cookie_id: str, cookie_value: str, user_id: int = None) -> bool:
        """保存Cookie到数据库，如存在则更新"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 如果没有提供user_id，尝试从现有记录获取，否则使用admin用户ID
                if user_id is None:
                    self._execute_sql(cursor, "SELECT user_id FROM cookies WHERE id = ?", (cookie_id,))
                    existing = cursor.fetchone()
                    if existing:
                        user_id = existing[0]
                    else:
                        # 获取admin用户ID作为默认值
                        self._execute_sql(cursor, "SELECT id FROM users WHERE username = 'admin'")
                        admin_user = cursor.fetchone()
                        user_id = admin_user[0] if admin_user else 1

                self._execute_sql(cursor,
                    "INSERT OR REPLACE INTO cookies (id, value, user_id) VALUES (?, ?, ?)",
                    (cookie_id, cookie_value, user_id)
                )

                self.conn.commit()
                logger.info(f"Cookie保存成功: {cookie_id} (用户ID: {user_id})")

                # 验证保存结果
                self._execute_sql(cursor, "SELECT user_id FROM cookies WHERE id = ?", (cookie_id,))
                saved_user_id = cursor.fetchone()
                if saved_user_id:
                    logger.info(f"Cookie保存验证: {cookie_id} 实际绑定到用户ID: {saved_user_id[0]}")
                else:
                    logger.error(f"Cookie保存验证失败: {cookie_id} 未找到记录")
                return True
            except Exception as e:
                logger.error(f"Cookie保存失败: {e}")
                self.conn.rollback()
                return False

    
    def delete_cookie(self, cookie_id: str) -> bool:
        """从数据库删除Cookie及其关键字"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 删除关联的关键字
                self._execute_sql(cursor, "DELETE FROM keywords WHERE cookie_id = ?", (cookie_id,))
                # 删除Cookie
                self._execute_sql(cursor, "DELETE FROM cookies WHERE id = ?", (cookie_id,))
                self.conn.commit()
                logger.debug(f"Cookie删除成功: {cookie_id}")
                return True
            except Exception as e:
                logger.error(f"Cookie删除失败: {e}")
                self.conn.rollback()
                return False
    
    def get_cookie(self, cookie_id: str) -> Optional[str]:
        """获取指定Cookie值"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT value FROM cookies WHERE id = ?", (cookie_id,))
                result = cursor.fetchone()
                return result[0] if result else None
            except Exception as e:
                logger.error(f"获取Cookie失败: {e}")
                return None
    
    def get_all_cookies(self, user_id: int = None) -> Dict[str, str]:
        """获取所有Cookie（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    self._execute_sql(cursor, "SELECT id, value FROM cookies WHERE user_id = ?", (user_id,))
                else:
                    self._execute_sql(cursor, "SELECT id, value FROM cookies")
                return {row[0]: row[1] for row in cursor.fetchall()}
            except Exception as e:
                logger.error(f"获取所有Cookie失败: {e}")
                return {}



    def get_cookie_by_id(self, cookie_id: str) -> Optional[Dict[str, str]]:
        """根据ID获取Cookie信息

        Args:
            cookie_id: Cookie ID

        Returns:
            Dict包含cookie信息，包括cookies_str字段，如果不存在返回None
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT id, value, created_at FROM cookies WHERE id = ?", (cookie_id,))
                result = cursor.fetchone()
                if result:
                    return {
                        'id': result[0],
                        'cookies_str': result[1],  # 使用cookies_str字段名以匹配调用方期望
                        'value': result[1],        # 保持向后兼容
                        'created_at': result[2]
                    }
                return None
            except Exception as e:
                logger.error(f"根据ID获取Cookie失败: {e}")
                return None

    def get_cookie_details(self, cookie_id: str) -> Optional[Dict[str, any]]:
        """获取Cookie的详细信息，包括user_id、auto_confirm、remark、pause_duration、username、password、show_browser和代理配置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, """
                    SELECT id, value, user_id, auto_confirm, remark, pause_duration, 
                           username, password, show_browser, created_at,
                           proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
                    FROM cookies WHERE id = ?
                """, (cookie_id,))
                result = cursor.fetchone()
                if result:
                    return {
                        'id': result[0],
                        'value': result[1],
                        'user_id': result[2],
                        'auto_confirm': bool(result[3]),
                        'remark': result[4] or '',
                        'pause_duration': result[5] if result[5] is not None else 10,  # 0是有效值，表示不暂停
                        'username': result[6] or '',
                        'password': result[7] or '',
                        'show_browser': bool(result[8]) if result[8] is not None else False,
                        'created_at': result[9],
                        # 代理配置
                        'proxy_type': result[10] or 'none',
                        'proxy_host': result[11] or '',
                        'proxy_port': result[12] or 0,
                        'proxy_user': result[13] or '',
                        'proxy_pass': result[14] or ''
                    }
                return None
            except Exception as e:
                logger.error(f"获取Cookie详细信息失败: {e}")
                return None

    def update_auto_confirm(self, cookie_id: str, auto_confirm: bool) -> bool:
        """更新Cookie的自动确认发货设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "UPDATE cookies SET auto_confirm = ? WHERE id = ?", (int(auto_confirm), cookie_id))
                self.conn.commit()
                logger.info(f"更新账号 {cookie_id} 自动确认发货设置: {'开启' if auto_confirm else '关闭'}")
                return True
            except Exception as e:
                logger.error(f"更新自动确认发货设置失败: {e}")
                return False

    def update_cookie_remark(self, cookie_id: str, remark: str) -> bool:
        """更新Cookie的备注"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "UPDATE cookies SET remark = ? WHERE id = ?", (remark, cookie_id))
                self.conn.commit()
                logger.info(f"更新账号 {cookie_id} 备注: {remark}")
                return True
            except Exception as e:
                logger.error(f"更新账号备注失败: {e}")
                return False

    def update_cookie_pause_duration(self, cookie_id: str, pause_duration: int) -> bool:
        """更新Cookie的自动回复暂停时间"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "UPDATE cookies SET pause_duration = ? WHERE id = ?", (pause_duration, cookie_id))
                self.conn.commit()
                logger.info(f"更新账号 {cookie_id} 自动回复暂停时间: {pause_duration}分钟")
                return True
            except Exception as e:
                logger.error(f"更新账号自动回复暂停时间失败: {e}")
                return False

    def get_cookie_pause_duration(self, cookie_id: str) -> int:
        """获取Cookie的自动回复暂停时间"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT pause_duration FROM cookies WHERE id = ?", (cookie_id,))
                result = cursor.fetchone()
                if result:
                    if result[0] is None:
                        logger.warning(f"账号 {cookie_id} 的pause_duration为NULL，使用默认值10分钟并修复数据库")
                        # 修复数据库中的NULL值
                        self._execute_sql(cursor, "UPDATE cookies SET pause_duration = 10 WHERE id = ?", (cookie_id,))
                        self.conn.commit()
                        return 10
                    return result[0]  # 返回实际值，包括0（0表示不暂停）
                else:
                    logger.warning(f"账号 {cookie_id} 未找到记录，使用默认值10分钟")
                    return 10
            except Exception as e:
                logger.error(f"获取账号自动回复暂停时间失败: {e}")
                return 10

    def update_cookie_account_info(self, cookie_id: str, cookie_value: str = None, username: str = None, password: str = None, show_browser: bool = None, user_id: int = None) -> bool:
        """更新Cookie的账号信息（包括cookie值、用户名、密码和显示浏览器设置）
        如果记录不存在，会先创建记录（需要提供cookie_value和user_id）
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 检查记录是否存在
                self._execute_sql(cursor, "SELECT id FROM cookies WHERE id = ?", (cookie_id,))
                exists = cursor.fetchone() is not None
                
                if not exists:
                    # 记录不存在，需要创建新记录
                    if cookie_value is None:
                        logger.warning(f"账号 {cookie_id} 不存在，且未提供cookie_value，无法创建新记录")
                        return False
                    
                    # 如果没有提供user_id，尝试从现有记录获取，否则使用admin用户ID
                    if user_id is None:
                        # 获取admin用户ID作为默认值
                        self._execute_sql(cursor, "SELECT id FROM users WHERE username = 'admin'")
                        admin_user = cursor.fetchone()
                        user_id = admin_user[0] if admin_user else 1
                    
                    # 构建插入语句
                    insert_fields = ['id', 'value', 'user_id']
                    insert_values = [cookie_id, cookie_value, user_id]
                    insert_placeholders = ['?', '?', '?']
                    
                    if username is not None:
                        insert_fields.append('username')
                        insert_values.append(username)
                        insert_placeholders.append('?')
                    
                    if password is not None:
                        insert_fields.append('password')
                        insert_values.append(password)
                        insert_placeholders.append('?')
                    
                    if show_browser is not None:
                        insert_fields.append('show_browser')
                        insert_values.append(1 if show_browser else 0)
                        insert_placeholders.append('?')
                    
                    sql = f"INSERT INTO cookies ({', '.join(insert_fields)}) VALUES ({', '.join(insert_placeholders)})"
                    self._execute_sql(cursor, sql, tuple(insert_values))
                    self.conn.commit()
                    logger.info(f"创建新账号 {cookie_id} 并保存信息成功: {insert_fields}")
                    return True
                else:
                    # 记录存在，执行更新
                    # 构建动态SQL更新语句
                    update_fields = []
                    params = []
                    
                    if cookie_value is not None:
                        update_fields.append("value = ?")
                        params.append(cookie_value)
                    
                    if username is not None:
                        update_fields.append("username = ?")
                        params.append(username)
                    
                    if password is not None:
                        update_fields.append("password = ?")
                        params.append(password)
                    
                    if show_browser is not None:
                        update_fields.append("show_browser = ?")
                        params.append(1 if show_browser else 0)
                    
                    if not update_fields:
                        logger.warning(f"更新账号 {cookie_id} 信息时没有提供任何更新字段")
                        return False
                    
                    params.append(cookie_id)
                    sql = f"UPDATE cookies SET {', '.join(update_fields)} WHERE id = ?"
                    
                    self._execute_sql(cursor, sql, tuple(params))
                    self.conn.commit()
                    logger.info(f"更新账号 {cookie_id} 信息成功: {update_fields}")
                    return True
            except Exception as e:
                logger.error(f"更新账号信息失败: {e}")
                import traceback
                logger.error(traceback.format_exc())
                self.conn.rollback()
                return False

    def update_cookie_proxy_config(self, cookie_id: str, proxy_type: str = None, proxy_host: str = None, 
                                     proxy_port: int = None, proxy_user: str = None, proxy_pass: str = None) -> bool:
        """更新Cookie的代理配置
        
        Args:
            cookie_id: Cookie ID
            proxy_type: 代理类型 (none/http/https/socks5)
            proxy_host: 代理服务器地址
            proxy_port: 代理端口
            proxy_user: 代理认证用户名（可选）
            proxy_pass: 代理认证密码（可选）
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 检查记录是否存在
                self._execute_sql(cursor, "SELECT id FROM cookies WHERE id = ?", (cookie_id,))
                if not cursor.fetchone():
                    logger.warning(f"账号 {cookie_id} 不存在，无法更新代理配置")
                    return False
                
                # 构建动态SQL更新语句
                update_fields = []
                params = []
                
                if proxy_type is not None:
                    update_fields.append("proxy_type = ?")
                    params.append(proxy_type)
                
                if proxy_host is not None:
                    update_fields.append("proxy_host = ?")
                    params.append(proxy_host)
                
                if proxy_port is not None:
                    update_fields.append("proxy_port = ?")
                    params.append(proxy_port)
                
                if proxy_user is not None:
                    update_fields.append("proxy_user = ?")
                    params.append(proxy_user)
                
                if proxy_pass is not None:
                    update_fields.append("proxy_pass = ?")
                    params.append(proxy_pass)
                
                if not update_fields:
                    logger.warning(f"更新账号 {cookie_id} 代理配置时没有提供任何更新字段")
                    return False
                
                params.append(cookie_id)
                sql = f"UPDATE cookies SET {', '.join(update_fields)} WHERE id = ?"
                
                self._execute_sql(cursor, sql, tuple(params))
                self.conn.commit()
                logger.info(f"更新账号 {cookie_id} 代理配置成功: type={proxy_type}, host={proxy_host}, port={proxy_port}")
                return True
            except Exception as e:
                logger.error(f"更新代理配置失败: {e}")
                import traceback
                logger.error(traceback.format_exc())
                self.conn.rollback()
                return False

    def get_cookie_proxy_config(self, cookie_id: str) -> Dict[str, any]:
        """获取Cookie的代理配置
        
        Returns:
            包含代理配置的字典，如果账号不存在则返回默认配置
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, """
                    SELECT proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass
                    FROM cookies WHERE id = ?
                """, (cookie_id,))
                result = cursor.fetchone()
                if result:
                    return {
                        'proxy_type': result[0] or 'none',
                        'proxy_host': result[1] or '',
                        'proxy_port': result[2] or 0,
                        'proxy_user': result[3] or '',
                        'proxy_pass': result[4] or ''
                    }
                # 返回默认配置
                return {
                    'proxy_type': 'none',
                    'proxy_host': '',
                    'proxy_port': 0,
                    'proxy_user': '',
                    'proxy_pass': ''
                }
            except Exception as e:
                logger.error(f"获取代理配置失败: {e}")
                return {
                    'proxy_type': 'none',
                    'proxy_host': '',
                    'proxy_port': 0,
                    'proxy_user': '',
                    'proxy_pass': ''
                }

    def get_auto_confirm(self, cookie_id: str) -> bool:
        """获取Cookie的自动确认发货设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT auto_confirm FROM cookies WHERE id = ?", (cookie_id,))
                result = cursor.fetchone()
                if result:
                    return bool(result[0])
                return True  # 默认开启
            except Exception as e:
                logger.error(f"获取自动确认发货设置失败: {e}")
                return True  # 出错时默认开启

    # -------------------- 自动好评操作 --------------------
    def get_auto_comment(self, cookie_id: str) -> bool:
        """获取Cookie的自动好评设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT auto_comment FROM cookies WHERE id = ?", (cookie_id,))
                result = cursor.fetchone()
                if result and result[0] is not None:
                    return bool(result[0])
                return False  # 默认关闭
            except Exception as e:
                logger.error(f"获取自动好评设置失败: {e}")
                return False  # 出错时默认关闭

    def update_auto_comment(self, cookie_id: str, auto_comment: bool) -> bool:
        """更新Cookie的自动好评设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "UPDATE cookies SET auto_comment = ? WHERE id = ?", (int(auto_comment), cookie_id))
                self.conn.commit()
                logger.info(f"更新账号 {cookie_id} 自动好评设置: {'开启' if auto_comment else '关闭'}")
                return True
            except Exception as e:
                logger.error(f"更新自动好评设置失败: {e}")
                return False

    def get_comment_templates(self, cookie_id: str) -> List[Dict]:
        """获取账号的好评模板列表"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, """
                    SELECT id, name, content, is_active, sort_order, created_at, updated_at 
                    FROM comment_templates 
                    WHERE cookie_id = ? 
                    ORDER BY sort_order, id
                """, (cookie_id,))
                results = cursor.fetchall()
                templates = []
                for row in results:
                    templates.append({
                        'id': row[0],
                        'name': row[1],
                        'content': row[2],
                        'is_active': bool(row[3]),
                        'sort_order': row[4],
                        'created_at': row[5],
                        'updated_at': row[6]
                    })
                return templates
            except Exception as e:
                logger.error(f"获取好评模板列表失败: {e}")
                return []

    def get_active_comment_template(self, cookie_id: str) -> Optional[Dict]:
        """获取账号当前激活的好评模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, """
                    SELECT id, name, content, is_active, sort_order, created_at, updated_at 
                    FROM comment_templates 
                    WHERE cookie_id = ? AND is_active = 1 
                    LIMIT 1
                """, (cookie_id,))
                result = cursor.fetchone()
                if result:
                    return {
                        'id': result[0],
                        'name': result[1],
                        'content': result[2],
                        'is_active': bool(result[3]),
                        'sort_order': result[4],
                        'created_at': result[5],
                        'updated_at': result[6]
                    }
                return None
            except Exception as e:
                logger.error(f"获取激活的好评模板失败: {e}")
                return None

    def add_comment_template(self, cookie_id: str, name: str, content: str, is_active: bool = False) -> Optional[int]:
        """添加好评模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 如果设置为激活状态，先将其他模板设为非激活
                if is_active:
                    self._execute_sql(cursor, "UPDATE comment_templates SET is_active = 0 WHERE cookie_id = ?", (cookie_id,))
                
                # 获取最大排序号
                self._execute_sql(cursor, "SELECT MAX(sort_order) FROM comment_templates WHERE cookie_id = ?", (cookie_id,))
                max_order = cursor.fetchone()[0]
                sort_order = (max_order or 0) + 1
                
                self._execute_sql(cursor, """
                    INSERT INTO comment_templates (cookie_id, name, content, is_active, sort_order) 
                    VALUES (?, ?, ?, ?, ?)
                """, (cookie_id, name, content, int(is_active), sort_order))
                
                template_id = cursor.lastrowid
                self.conn.commit()
                logger.info(f"添加好评模板成功: cookie_id={cookie_id}, name={name}, id={template_id}")
                return template_id
            except Exception as e:
                logger.error(f"添加好评模板失败: {e}")
                self.conn.rollback()
                return None

    def update_comment_template(self, template_id: int, name: str = None, content: str = None, is_active: bool = None) -> bool:
        """更新好评模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 获取模板所属的cookie_id
                self._execute_sql(cursor, "SELECT cookie_id FROM comment_templates WHERE id = ?", (template_id,))
                result = cursor.fetchone()
                if not result:
                    logger.warning(f"好评模板不存在: id={template_id}")
                    return False
                cookie_id = result[0]
                
                # 如果设置为激活状态，先将其他模板设为非激活
                if is_active:
                    self._execute_sql(cursor, "UPDATE comment_templates SET is_active = 0 WHERE cookie_id = ?", (cookie_id,))
                
                # 构建动态更新语句
                update_fields = []
                params = []
                
                if name is not None:
                    update_fields.append("name = ?")
                    params.append(name)
                
                if content is not None:
                    update_fields.append("content = ?")
                    params.append(content)
                
                if is_active is not None:
                    update_fields.append("is_active = ?")
                    params.append(int(is_active))
                
                if not update_fields:
                    return True
                
                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                params.append(template_id)
                
                sql = f"UPDATE comment_templates SET {', '.join(update_fields)} WHERE id = ?"
                self._execute_sql(cursor, sql, tuple(params))
                self.conn.commit()
                logger.info(f"更新好评模板成功: id={template_id}")
                return True
            except Exception as e:
                logger.error(f"更新好评模板失败: {e}")
                self.conn.rollback()
                return False

    def delete_comment_template(self, template_id: int) -> bool:
        """删除好评模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "DELETE FROM comment_templates WHERE id = ?", (template_id,))
                self.conn.commit()
                logger.info(f"删除好评模板成功: id={template_id}")
                return True
            except Exception as e:
                logger.error(f"删除好评模板失败: {e}")
                self.conn.rollback()
                return False

    def set_active_comment_template(self, cookie_id: str, template_id: int) -> bool:
        """设置激活的好评模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 先将所有模板设为非激活
                self._execute_sql(cursor, "UPDATE comment_templates SET is_active = 0 WHERE cookie_id = ?", (cookie_id,))
                # 设置指定模板为激活
                self._execute_sql(cursor, "UPDATE comment_templates SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND cookie_id = ?", (template_id, cookie_id))
                self.conn.commit()
                logger.info(f"设置激活好评模板: cookie_id={cookie_id}, template_id={template_id}")
                return True
            except Exception as e:
                logger.error(f"设置激活好评模板失败: {e}")
                self.conn.rollback()
                return False
    
    # -------------------- 关键字操作 --------------------
    def save_keywords(self, cookie_id: str, keywords: List[Tuple[str, str]]) -> bool:
        """保存关键字列表，先删除旧数据再插入新数据（向后兼容方法）"""
        # 转换为新格式（不包含item_id）
        keywords_with_item_id = [(keyword, reply, None) for keyword, reply in keywords]
        return self.save_keywords_with_item_id(cookie_id, keywords_with_item_id)

    def save_keywords_with_item_id(self, cookie_id: str, keywords: List[Tuple[str, str, str]]) -> bool:
        """保存关键字列表（包含商品ID），先删除旧数据再插入新数据"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 先删除该cookie_id的所有关键字
                self._execute_sql(cursor, "DELETE FROM keywords WHERE cookie_id = ?", (cookie_id,))

                # 插入新关键字，使用INSERT OR REPLACE来处理可能的唯一约束冲突
                for keyword, reply, item_id in keywords:
                    # 标准化item_id：空字符串转为NULL
                    normalized_item_id = item_id if item_id and item_id.strip() else None

                    try:
                        self._execute_sql(cursor,
                            "INSERT INTO keywords (cookie_id, keyword, reply, item_id) VALUES (?, ?, ?, ?)",
                            (cookie_id, keyword, reply, normalized_item_id))
                    except sqlite3.IntegrityError as ie:
                        # 如果遇到唯一约束冲突，记录详细错误信息
                        item_desc = f"商品ID: {normalized_item_id}" if normalized_item_id else "通用关键词"
                        logger.error(f"关键词唯一约束冲突: Cookie={cookie_id}, 关键词='{keyword}', {item_desc}")
                        raise ie

                self.conn.commit()
                logger.info(f"关键字保存成功: {cookie_id}, {len(keywords)}条")
                return True
            except Exception as e:
                logger.error(f"关键字保存失败: {e}")
                self.conn.rollback()
                return False

    def save_text_keywords_only(self, cookie_id: str, keywords: List[Tuple[str, str, str]]) -> bool:
        """保存文本关键字列表，只删除文本类型的关键词，保留图片关键词"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 检查是否与现有图片关键词冲突
                for keyword, reply, item_id in keywords:
                    normalized_item_id = item_id if item_id and item_id.strip() else None

                    # 检查是否存在同名的图片关键词
                    if normalized_item_id:
                        # 有商品ID的情况：检查 (cookie_id, keyword, item_id) 是否存在图片关键词
                        self._execute_sql(cursor,
                            "SELECT type FROM keywords WHERE cookie_id = ? AND keyword = ? AND item_id = ? AND type = 'image'",
                            (cookie_id, keyword, normalized_item_id))
                    else:
                        # 通用关键词的情况：检查 (cookie_id, keyword) 是否存在图片关键词
                        self._execute_sql(cursor,
                            "SELECT type FROM keywords WHERE cookie_id = ? AND keyword = ? AND (item_id IS NULL OR item_id = '') AND type = 'image'",
                            (cookie_id, keyword))

                    if cursor.fetchone():
                        # 存在同名图片关键词，抛出友好的错误信息
                        item_desc = f"商品ID: {normalized_item_id}" if normalized_item_id else "通用关键词"
                        error_msg = f"关键词 '{keyword}' （{item_desc}） 已存在（图片关键词），无法保存为文本关键词"
                        logger.warning(f"文本关键词与图片关键词冲突: Cookie={cookie_id}, 关键词='{keyword}', {item_desc}")
                        raise ValueError(error_msg)

                # 只删除该cookie_id的文本类型关键字，保留图片关键词
                self._execute_sql(cursor,
                    "DELETE FROM keywords WHERE cookie_id = ? AND (type IS NULL OR type = 'text')",
                    (cookie_id,))

                # 插入新的文本关键字
                for keyword, reply, item_id in keywords:
                    # 标准化item_id：空字符串转为NULL
                    normalized_item_id = item_id if item_id and item_id.strip() else None

                    self._execute_sql(cursor,
                        "INSERT INTO keywords (cookie_id, keyword, reply, item_id, type) VALUES (?, ?, ?, ?, 'text')",
                        (cookie_id, keyword, reply, normalized_item_id))

                self.conn.commit()
                logger.info(f"文本关键字保存成功: {cookie_id}, {len(keywords)}条，图片关键词已保留")
                return True
            except ValueError:
                # 重新抛出友好的错误信息
                raise
            except Exception as e:
                logger.error(f"文本关键字保存失败: {e}")
                self.conn.rollback()
                return False
    
    def get_keywords(self, cookie_id: str) -> List[Tuple[str, str]]:
        """获取指定Cookie的关键字列表（向后兼容方法）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT keyword, reply FROM keywords WHERE cookie_id = ?", (cookie_id,))
                return [(row[0], row[1]) for row in cursor.fetchall()]
            except Exception as e:
                logger.error(f"获取关键字失败: {e}")
                return []

    def get_keywords_with_item_id(self, cookie_id: str) -> List[Tuple[str, str, str]]:
        """获取指定Cookie的关键字列表（包含商品ID）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT keyword, reply, item_id FROM keywords WHERE cookie_id = ?", (cookie_id,))
                return [(row[0], row[1], row[2]) for row in cursor.fetchall()]
            except Exception as e:
                logger.error(f"获取关键字失败: {e}")
                return []

    def check_keyword_duplicate(self, cookie_id: str, keyword: str, item_id: str = None) -> bool:
        """检查关键词是否重复"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if item_id:
                    # 如果有商品ID，检查相同cookie_id、keyword、item_id的组合
                    self._execute_sql(cursor,
                        "SELECT COUNT(*) FROM keywords WHERE cookie_id = ? AND keyword = ? AND item_id = ?",
                        (cookie_id, keyword, item_id))
                else:
                    # 如果没有商品ID，检查相同cookie_id、keyword且item_id为空的组合
                    self._execute_sql(cursor,
                        "SELECT COUNT(*) FROM keywords WHERE cookie_id = ? AND keyword = ? AND (item_id IS NULL OR item_id = '')",
                        (cookie_id, keyword))

                count = cursor.fetchone()[0]
                return count > 0
            except Exception as e:
                logger.error(f"检查关键词重复失败: {e}")
                return False

    def save_image_keyword(self, cookie_id: str, keyword: str, image_url: str, item_id: str = None) -> bool:
        """保存图片关键词（调用前应先检查重复）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 标准化item_id：空字符串转为NULL
                normalized_item_id = item_id if item_id and item_id.strip() else None

                # 直接插入图片关键词（重复检查应在调用前完成）
                self._execute_sql(cursor,
                    "INSERT INTO keywords (cookie_id, keyword, reply, item_id, type, image_url) VALUES (?, ?, ?, ?, ?, ?)",
                    (cookie_id, keyword, '', normalized_item_id, 'image', image_url))

                self.conn.commit()
                logger.info(f"图片关键词保存成功: {cookie_id}, 关键词: {keyword}, 图片: {image_url}")
                return True
            except Exception as e:
                logger.error(f"图片关键词保存失败: {e}")
                self.conn.rollback()
                return False

    def get_keywords_with_type(self, cookie_id: str) -> List[Dict[str, any]]:
        """获取指定Cookie的关键字列表（包含类型信息和商品名称）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 关联查询商品信息表，获取商品名称
                self._execute_sql(cursor,
                    """SELECT k.keyword, k.reply, k.item_id, k.type, k.image_url, i.item_title 
                    FROM keywords k 
                    LEFT JOIN item_info i ON k.item_id = i.item_id AND k.cookie_id = i.cookie_id 
                    WHERE k.cookie_id = ?""",
                    (cookie_id,))

                results = []
                for row in cursor.fetchall():
                    keyword_data = {
                        'keyword': row[0],
                        'reply': row[1],
                        'item_id': row[2],
                        'type': row[3] or 'text',  # 默认为text类型
                        'image_url': row[4],
                        'item_title': row[5]  # 添加商品名称
                    }
                    results.append(keyword_data)

                return results
            except Exception as e:
                logger.error(f"获取关键字失败: {e}")
                return []

    def update_keyword_image_url(self, cookie_id: str, keyword: str, new_image_url: str) -> bool:
        """更新关键词的图片URL"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 更新图片URL
                self._execute_sql(cursor,
                    "UPDATE keywords SET image_url = ? WHERE cookie_id = ? AND keyword = ? AND type = 'image'",
                    (new_image_url, cookie_id, keyword))

                self.conn.commit()

                # 检查是否有行被更新
                if cursor.rowcount > 0:
                    logger.info(f"关键词图片URL更新成功: {cookie_id}, 关键词: {keyword}, 新URL: {new_image_url}")
                    return True
                else:
                    logger.warning(f"未找到匹配的图片关键词: {cookie_id}, 关键词: {keyword}")
                    return False

            except Exception as e:
                logger.error(f"更新关键词图片URL失败: {e}")
                self.conn.rollback()
                return False

    def delete_keyword_by_index(self, cookie_id: str, index: int) -> bool:
        """根据索引删除关键词"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 先获取所有关键词
                self._execute_sql(cursor,
                    "SELECT rowid FROM keywords WHERE cookie_id = ? ORDER BY rowid",
                    (cookie_id,))
                rows = cursor.fetchall()

                if 0 <= index < len(rows):
                    rowid = rows[index][0]
                    self._execute_sql(cursor, "DELETE FROM keywords WHERE rowid = ?", (rowid,))
                    self.conn.commit()
                    logger.info(f"删除关键词成功: {cookie_id}, 索引: {index}")
                    return True
                else:
                    logger.warning(f"关键词索引超出范围: {index}")
                    return False

            except Exception as e:
                logger.error(f"删除关键词失败: {e}")
                self.conn.rollback()
                return False


    def get_all_keywords(self, user_id: int = None) -> Dict[str, List[Tuple[str, str]]]:
        """获取所有Cookie的关键字（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    cursor.execute("""
                    SELECT k.cookie_id, k.keyword, k.reply
                    FROM keywords k
                    JOIN cookies c ON k.cookie_id = c.id
                    WHERE c.user_id = ?
                    """, (user_id,))
                else:
                    self._execute_sql(cursor, "SELECT cookie_id, keyword, reply FROM keywords")

                result = {}
                for row in cursor.fetchall():
                    cookie_id, keyword, reply = row
                    if cookie_id not in result:
                        result[cookie_id] = []
                    result[cookie_id].append((keyword, reply))

                return result
            except Exception as e:
                logger.error(f"获取所有关键字失败: {e}")
                return {}

    def save_cookie_status(self, cookie_id: str, enabled: bool):
        """保存Cookie的启用状态"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO cookie_status (cookie_id, enabled, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (cookie_id, enabled))
                self.conn.commit()
                logger.debug(f"保存Cookie状态: {cookie_id} -> {'启用' if enabled else '禁用'}")
            except Exception as e:
                logger.error(f"保存Cookie状态失败: {e}")
                raise

    def get_cookie_status(self, cookie_id: str) -> bool:
        """获取Cookie的启用状态"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT enabled FROM cookie_status WHERE cookie_id = ?', (cookie_id,))
                result = cursor.fetchone()
                return bool(result[0]) if result else True  # 默认启用
            except Exception as e:
                logger.error(f"获取Cookie状态失败: {e}")
                return True  # 出错时默认启用

    def get_all_cookie_status(self) -> Dict[str, bool]:
        """获取所有Cookie的启用状态"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT cookie_id, enabled FROM cookie_status')

                result = {}
                for row in cursor.fetchall():
                    cookie_id, enabled = row
                    result[cookie_id] = bool(enabled)

                return result
            except Exception as e:
                logger.error(f"获取所有Cookie状态失败: {e}")
                return {}

    # -------------------- AI回复设置操作 --------------------
    def save_ai_reply_settings(self, cookie_id: str, settings: dict) -> bool:
        """保存AI回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO ai_reply_settings
                (cookie_id, ai_enabled, model_name, api_key, base_url,
                 max_discount_percent, max_discount_amount, max_bargain_rounds,
                 custom_prompts, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    cookie_id,
                    settings.get('ai_enabled', False),
                    settings.get('model_name', 'qwen-plus'),
                    settings.get('api_key', ''),
                    settings.get('base_url', 'https://dashscope.aliyuncs.com/compatible-mode/v1'),
                    settings.get('max_discount_percent', 10),
                    settings.get('max_discount_amount', 100),
                    settings.get('max_bargain_rounds', 3),
                    settings.get('custom_prompts', '')
                ))
                self.conn.commit()
                logger.debug(f"AI回复设置保存成功: {cookie_id}")
                return True
            except Exception as e:
                logger.error(f"保存AI回复设置失败: {e}")
                self.conn.rollback()
                return False

    def get_ai_reply_settings(self, cookie_id: str) -> dict:
        """获取AI回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT ai_enabled, model_name, api_key, base_url,
                       max_discount_percent, max_discount_amount, max_bargain_rounds,
                       custom_prompts
                FROM ai_reply_settings WHERE cookie_id = ?
                ''', (cookie_id,))

                result = cursor.fetchone()
                if result:
                    return {
                        'ai_enabled': bool(result[0]),
                        'model_name': result[1],
                        'api_key': result[2],
                        'base_url': result[3],
                        'max_discount_percent': result[4],
                        'max_discount_amount': result[5],
                        'max_bargain_rounds': result[6],
                        'custom_prompts': result[7]
                    }
                else:
                    # 返回默认设置
                    return {
                        'ai_enabled': False,
                        'model_name': 'qwen-plus',
                        'api_key': '',
                        'base_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
                        'max_discount_percent': 10,
                        'max_discount_amount': 100,
                        'max_bargain_rounds': 3,
                        'custom_prompts': ''
                    }
            except Exception as e:
                logger.error(f"获取AI回复设置失败: {e}")
                return {
                    'ai_enabled': False,
                    'model_name': 'qwen-plus',
                    'api_key': '',
                    'base_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
                    'max_discount_percent': 10,
                    'max_discount_amount': 100,
                    'max_bargain_rounds': 3,
                    'custom_prompts': ''
                }

    def get_all_ai_reply_settings(self) -> Dict[str, dict]:
        """获取所有账号的AI回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT cookie_id, ai_enabled, model_name, api_key, base_url,
                       max_discount_percent, max_discount_amount, max_bargain_rounds,
                       custom_prompts
                FROM ai_reply_settings
                ''')

                result = {}
                for row in cursor.fetchall():
                    cookie_id = row[0]
                    result[cookie_id] = {
                        'ai_enabled': bool(row[1]),
                        'model_name': row[2],
                        'api_key': row[3],
                        'base_url': row[4],
                        'max_discount_percent': row[5],
                        'max_discount_amount': row[6],
                        'max_bargain_rounds': row[7],
                        'custom_prompts': row[8]
                    }

                return result
            except Exception as e:
                logger.error(f"获取所有AI回复设置失败: {e}")
                return {}

    # -------------------- 默认回复操作 --------------------
    def save_default_reply(self, cookie_id: str, enabled: bool, reply_content: str = None, reply_once: bool = False):
        """保存默认回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO default_replies (cookie_id, enabled, reply_content, reply_once, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (cookie_id, enabled, reply_content, reply_once))
                self.conn.commit()
                logger.debug(f"保存默认回复设置: {cookie_id} -> {'启用' if enabled else '禁用'}, 只回复一次: {'是' if reply_once else '否'}")
            except Exception as e:
                logger.error(f"保存默认回复设置失败: {e}")
                raise

    def get_default_reply(self, cookie_id: str) -> Optional[Dict[str, any]]:
        """获取指定账号的默认回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT enabled, reply_content, reply_once FROM default_replies WHERE cookie_id = ?
                ''', (cookie_id,))
                result = cursor.fetchone()
                if result:
                    enabled, reply_content, reply_once = result
                    return {
                        'enabled': bool(enabled),
                        'reply_content': reply_content or '',
                        'reply_once': bool(reply_once) if reply_once is not None else False
                    }
                return None
            except Exception as e:
                logger.error(f"获取默认回复设置失败: {e}")
                return None

    def get_all_default_replies(self) -> Dict[str, Dict[str, any]]:
        """获取所有账号的默认回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT cookie_id, enabled, reply_content, reply_once FROM default_replies')

                result = {}
                for row in cursor.fetchall():
                    cookie_id, enabled, reply_content, reply_once = row
                    result[cookie_id] = {
                        'enabled': bool(enabled),
                        'reply_content': reply_content or '',
                        'reply_once': bool(reply_once) if reply_once is not None else False
                    }

                return result
            except Exception as e:
                logger.error(f"获取所有默认回复设置失败: {e}")
                return {}

    def add_default_reply_record(self, cookie_id: str, chat_id: str):
        """记录已回复的chat_id"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR IGNORE INTO default_reply_records (cookie_id, chat_id)
                VALUES (?, ?)
                ''', (cookie_id, chat_id))
                self.conn.commit()
                logger.debug(f"记录默认回复: {cookie_id} -> {chat_id}")
            except Exception as e:
                logger.error(f"记录默认回复失败: {e}")

    def has_default_reply_record(self, cookie_id: str, chat_id: str) -> bool:
        """检查是否已经回复过该chat_id"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT 1 FROM default_reply_records WHERE cookie_id = ? AND chat_id = ?
                ''', (cookie_id, chat_id))
                result = cursor.fetchone()
                return result is not None
            except Exception as e:
                logger.error(f"检查默认回复记录失败: {e}")
                return False

    def clear_default_reply_records(self, cookie_id: str):
        """清空指定账号的默认回复记录"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM default_reply_records WHERE cookie_id = ?', (cookie_id,))
                self.conn.commit()
                logger.debug(f"清空默认回复记录: {cookie_id}")
            except Exception as e:
                logger.error(f"清空默认回复记录失败: {e}")

    def delete_default_reply(self, cookie_id: str) -> bool:
        """删除指定账号的默认回复设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "DELETE FROM default_replies WHERE cookie_id = ?", (cookie_id,))
                self.conn.commit()
                logger.debug(f"删除默认回复设置: {cookie_id}")
                return True
            except Exception as e:
                logger.error(f"删除默认回复设置失败: {e}")
                self.conn.rollback()
                return False

    # -------------------- 通知渠道操作 --------------------
    def create_notification_channel(self, name: str, channel_type: str, config: str, user_id: int = None) -> int:
        """创建通知渠道"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT INTO notification_channels (name, type, config, user_id)
                VALUES (?, ?, ?, ?)
                ''', (name, channel_type, config, user_id))
                self.conn.commit()
                channel_id = cursor.lastrowid
                logger.debug(f"创建通知渠道: {name} (ID: {channel_id})")
                return channel_id
            except Exception as e:
                logger.error(f"创建通知渠道失败: {e}")
                self.conn.rollback()
                raise

    def get_notification_channels(self, user_id: int = None) -> List[Dict[str, any]]:
        """获取所有通知渠道"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    cursor.execute('''
                    SELECT id, name, type, config, enabled, created_at, updated_at
                    FROM notification_channels
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    ''', (user_id,))
                else:
                    cursor.execute('''
                    SELECT id, name, type, config, enabled, created_at, updated_at
                    FROM notification_channels
                    ORDER BY created_at DESC
                    ''')

                channels = []
                for row in cursor.fetchall():
                    channels.append({
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'config': row[3],
                        'enabled': bool(row[4]),
                        'created_at': row[5],
                        'updated_at': row[6]
                    })

                return channels
            except Exception as e:
                logger.error(f"获取通知渠道失败: {e}")
                return []

    def get_notification_channel(self, channel_id: int) -> Optional[Dict[str, any]]:
        """获取指定通知渠道"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT id, name, type, config, enabled, created_at, updated_at
                FROM notification_channels WHERE id = ?
                ''', (channel_id,))

                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'config': row[3],
                        'enabled': bool(row[4]),
                        'created_at': row[5],
                        'updated_at': row[6]
                    }
                return None
            except Exception as e:
                logger.error(f"获取通知渠道失败: {e}")
                return None

    def update_notification_channel(self, channel_id: int, name: str, config: str, enabled: bool = True) -> bool:
        """更新通知渠道"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                UPDATE notification_channels
                SET name = ?, config = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''', (name, config, enabled, channel_id))
                self.conn.commit()
                logger.debug(f"更新通知渠道: {channel_id}")
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"更新通知渠道失败: {e}")
                self.conn.rollback()
                return False

    def delete_notification_channel(self, channel_id: int) -> bool:
        """删除通知渠道"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "DELETE FROM notification_channels WHERE id = ?", (channel_id,))
                self.conn.commit()
                logger.debug(f"删除通知渠道: {channel_id}")
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"删除通知渠道失败: {e}")
                self.conn.rollback()
                return False

    # -------------------- 消息通知配置操作 --------------------
    def set_message_notification(self, cookie_id: str, channel_id: int, enabled: bool = True) -> bool:
        """设置账号的消息通知"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO message_notifications (cookie_id, channel_id, enabled)
                VALUES (?, ?, ?)
                ''', (cookie_id, channel_id, enabled))
                self.conn.commit()
                logger.debug(f"设置消息通知: {cookie_id} -> {channel_id}")
                return True
            except Exception as e:
                logger.error(f"设置消息通知失败: {e}")
                self.conn.rollback()
                return False

    def get_account_notifications(self, cookie_id: str) -> List[Dict[str, any]]:
        """获取账号的通知配置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT mn.id, mn.channel_id, mn.enabled, nc.name, nc.type, nc.config
                FROM message_notifications mn
                JOIN notification_channels nc ON mn.channel_id = nc.id
                WHERE mn.cookie_id = ? AND nc.enabled = 1
                ORDER BY mn.id
                ''', (cookie_id,))

                notifications = []
                for row in cursor.fetchall():
                    notifications.append({
                        'id': row[0],
                        'channel_id': row[1],
                        'enabled': bool(row[2]),
                        'channel_name': row[3],
                        'channel_type': row[4],
                        'channel_config': row[5]
                    })

                return notifications
            except Exception as e:
                logger.error(f"获取账号通知配置失败: {e}")
                return []

    def get_all_message_notifications(self) -> Dict[str, List[Dict[str, any]]]:
        """获取所有账号的通知配置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT mn.cookie_id, mn.id, mn.channel_id, mn.enabled, nc.name, nc.type, nc.config
                FROM message_notifications mn
                JOIN notification_channels nc ON mn.channel_id = nc.id
                WHERE nc.enabled = 1
                ORDER BY mn.cookie_id, mn.id
                ''')

                result = {}
                for row in cursor.fetchall():
                    cookie_id = row[0]
                    if cookie_id not in result:
                        result[cookie_id] = []

                    result[cookie_id].append({
                        'id': row[1],
                        'channel_id': row[2],
                        'enabled': bool(row[3]),
                        'channel_name': row[4],
                        'channel_type': row[5],
                        'channel_config': row[6]
                    })

                return result
            except Exception as e:
                logger.error(f"获取所有消息通知配置失败: {e}")
                return {}

    def delete_message_notification(self, notification_id: int) -> bool:
        """删除消息通知配置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "DELETE FROM message_notifications WHERE id = ?", (notification_id,))
                self.conn.commit()
                logger.debug(f"删除消息通知配置: {notification_id}")
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"删除消息通知配置失败: {e}")
                self.conn.rollback()
                return False

    def delete_account_notifications(self, cookie_id: str) -> bool:
        """删除账号的所有消息通知配置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "DELETE FROM message_notifications WHERE cookie_id = ?", (cookie_id,))
                self.conn.commit()
                logger.debug(f"删除账号通知配置: {cookie_id}")
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"删除账号通知配置失败: {e}")
                self.conn.rollback()
                return False

    # -------------------- 通知模板操作 --------------------
    def get_all_notification_templates(self) -> List[Dict[str, any]]:
        """获取所有通知模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT id, type, template, created_at, updated_at
                FROM notification_templates
                ORDER BY id
                ''')

                templates = []
                for row in cursor.fetchall():
                    templates.append({
                        'id': row[0],
                        'type': row[1],
                        'template': row[2],
                        'created_at': row[3],
                        'updated_at': row[4]
                    })

                return templates
            except Exception as e:
                logger.error(f"获取通知模板失败: {e}")
                return []

    def get_notification_template(self, template_type: str) -> Optional[Dict[str, any]]:
        """获取指定类型的通知模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT id, type, template, created_at, updated_at
                FROM notification_templates
                WHERE type = ?
                ''', (template_type,))

                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'type': row[1],
                        'template': row[2],
                        'created_at': row[3],
                        'updated_at': row[4]
                    }
                return None
            except Exception as e:
                logger.error(f"获取通知模板失败: {e}")
                return None

    def update_notification_template(self, template_type: str, template: str) -> bool:
        """更新通知模板"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, '''
                UPDATE notification_templates
                SET template = ?, updated_at = CURRENT_TIMESTAMP
                WHERE type = ?
                ''', (template, template_type))
                self.conn.commit()
                logger.info(f"更新通知模板: {template_type}")
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"更新通知模板失败: {e}")
                self.conn.rollback()
                return False

    def reset_notification_template(self, template_type: str) -> bool:
        """重置通知模板为默认值"""
        default_templates = {
            'message': '''🚨 接收消息通知

账号: {account_id}
买家: {buyer_name} (ID: {buyer_id})
商品ID: {item_id}
聊天ID: {chat_id}
消息内容: {message}

时间: {time}''',
            'token_refresh': '''Token刷新异常

账号ID: {account_id}
异常时间: {time}
异常信息: {error_message}

请检查账号Cookie是否过期，如有需要请及时更新Cookie配置。''',
            'delivery': '''🚨 自动发货通知

账号: {account_id}
买家: {buyer_name} (ID: {buyer_id})
商品ID: {item_id}
聊天ID: {chat_id}
结果: {result}
时间: {time}

请及时处理！''',
            'slider_success': '''✅ 滑块验证成功，cookies已自动更新到数据库

账号: {account_id}
时间: {time}''',
            'face_verify': '''⚠️ 账号密码登录需要人脸验证

账号: {account_id}
时间: {time}

请点击验证链接完成验证:
{verification_url}

在验证期间，闲鱼自动回复暂时无法使用。''',
            'password_login_success': '''✅ 密码登录成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号Cookie已更新，正在重启服务...''',
            'cookie_refresh_success': '''✅ 刷新Cookie成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号已可正常使用。'''
        }

        if template_type not in default_templates:
            logger.error(f"未知的模板类型: {template_type}")
            return False

        return self.update_notification_template(template_type, default_templates[template_type])

    def get_default_notification_template(self, template_type: str) -> Optional[str]:
        """获取默认通知模板"""
        default_templates = {
            'message': '''🚨 接收消息通知

账号: {account_id}
买家: {buyer_name} (ID: {buyer_id})
商品ID: {item_id}
聊天ID: {chat_id}
消息内容: {message}

时间: {time}''',
            'token_refresh': '''Token刷新异常

账号ID: {account_id}
异常时间: {time}
异常信息: {error_message}

请检查账号Cookie是否过期，如有需要请及时更新Cookie配置。''',
            'delivery': '''🚨 自动发货通知

账号: {account_id}
买家: {buyer_name} (ID: {buyer_id})
商品ID: {item_id}
聊天ID: {chat_id}
结果: {result}
时间: {time}

请及时处理！''',
            'slider_success': '''✅ 滑块验证成功，cookies已自动更新到数据库

账号: {account_id}
时间: {time}''',
            'face_verify': '''⚠️ 账号密码登录需要人脸验证

账号: {account_id}
时间: {time}

请点击验证链接完成验证:
{verification_url}

在验证期间，闲鱼自动回复暂时无法使用。''',
            'password_login_success': '''✅ 密码登录成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号Cookie已更新，正在重启服务...''',
            'cookie_refresh_success': '''✅ 刷新Cookie成功

账号: {account_id}
时间: {time}
Cookie数量: {cookie_count}

账号已可正常使用。'''
        }

        return default_templates.get(template_type)

    # -------------------- 备份和恢复操作 --------------------
    def export_backup(self, user_id: int = None) -> Dict[str, any]:
        """导出系统备份数据（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                backup_data = {
                    'version': '1.0',
                    'timestamp': time.time(),
                    'user_id': user_id,
                    'data': {}
                }

                if user_id is not None:
                    # 用户级备份：只备份该用户的数据
                    # 备份用户的cookies
                    self._execute_sql(cursor, "SELECT * FROM cookies WHERE user_id = ?", (user_id,))
                    columns = [description[0] for description in cursor.description]
                    rows = cursor.fetchall()
                    backup_data['data']['cookies'] = {
                        'columns': columns,
                        'rows': [list(row) for row in rows]
                    }

                    # 备份用户cookies相关的其他数据
                    user_cookie_ids = [row[0] for row in rows]  # 获取用户的cookie_id列表

                    if user_cookie_ids:
                        placeholders = ','.join(['?' for _ in user_cookie_ids])

                        # 备份关键字
                        cursor.execute(f"SELECT * FROM keywords WHERE cookie_id IN ({placeholders})", user_cookie_ids)
                        columns = [description[0] for description in cursor.description]
                        rows = cursor.fetchall()
                        backup_data['data']['keywords'] = {
                            'columns': columns,
                            'rows': [list(row) for row in rows]
                        }

                        # 备份其他相关表
                        related_tables = ['cookie_status', 'default_replies', 'message_notifications',
                                        'item_info', 'ai_reply_settings', 'ai_conversations']

                        for table in related_tables:
                            cursor.execute(f"SELECT * FROM {table} WHERE cookie_id IN ({placeholders})", user_cookie_ids)
                            columns = [description[0] for description in cursor.description]
                            rows = cursor.fetchall()
                            backup_data['data'][table] = {
                                'columns': columns,
                                'rows': [list(row) for row in rows]
                            }
                else:
                    # 系统级备份：备份所有数据
                    tables = [
                        'cookies', 'keywords', 'cookie_status', 'cards',
                        'delivery_rules', 'default_replies', 'notification_channels',
                        'message_notifications', 'system_settings', 'item_info',
                        'ai_reply_settings', 'ai_conversations', 'ai_item_cache'
                    ]

                    for table in tables:
                        cursor.execute(f"SELECT * FROM {table}")
                        columns = [description[0] for description in cursor.description]
                        rows = cursor.fetchall()

                        backup_data['data'][table] = {
                            'columns': columns,
                            'rows': [list(row) for row in rows]
                        }

                logger.info(f"导出备份成功，用户ID: {user_id}")
                return backup_data

            except Exception as e:
                logger.error(f"导出备份失败: {e}")
                raise

    def import_backup(self, backup_data: Dict[str, any], user_id: int = None) -> bool:
        """导入系统备份数据（支持用户隔离）"""
        with self.lock:
            try:
                # 验证备份数据格式
                if not isinstance(backup_data, dict) or 'data' not in backup_data:
                    raise ValueError("备份数据格式无效")

                # 开始事务
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "BEGIN TRANSACTION")

                if user_id is not None:
                    # 用户级导入：只清空该用户的数据
                    # 获取用户的cookie_id列表
                    self._execute_sql(cursor, "SELECT id FROM cookies WHERE user_id = ?", (user_id,))
                    user_cookie_ids = [row[0] for row in cursor.fetchall()]

                    if user_cookie_ids:
                        placeholders = ','.join(['?' for _ in user_cookie_ids])

                        # 删除用户相关数据
                        related_tables = ['message_notifications', 'default_replies', 'item_info',
                                        'cookie_status', 'keywords', 'ai_conversations', 'ai_reply_settings']

                        for table in related_tables:
                            cursor.execute(f"DELETE FROM {table} WHERE cookie_id IN ({placeholders})", user_cookie_ids)

                        # 删除用户的cookies
                        self._execute_sql(cursor, "DELETE FROM cookies WHERE user_id = ?", (user_id,))
                else:
                    # 系统级导入：清空所有数据（除了用户和管理员密码）
                    tables = [
                        'message_notifications', 'notification_channels', 'default_replies',
                        'delivery_rules', 'cards', 'item_info', 'cookie_status', 'keywords',
                        'ai_conversations', 'ai_reply_settings', 'ai_item_cache', 'cookies'
                    ]

                    for table in tables:
                        cursor.execute(f"DELETE FROM {table}")

                    # 清空系统设置（保留管理员密码）
                    self._execute_sql(cursor, "DELETE FROM system_settings WHERE key != 'admin_password_hash'")

                # 导入数据
                data = backup_data['data']
                for table_name, table_data in data.items():
                    if table_name not in ['cookies', 'keywords', 'cookie_status', 'cards',
                                        'delivery_rules', 'default_replies', 'notification_channels',
                                        'message_notifications', 'system_settings', 'item_info',
                                        'ai_reply_settings', 'ai_conversations', 'ai_item_cache']:
                        continue

                    columns = table_data['columns']
                    rows = table_data['rows']

                    if not rows:
                        continue

                    # 如果是用户级导入，需要确保cookies表的user_id正确
                    if user_id is not None and table_name == 'cookies':
                        # 更新所有导入的cookies的user_id
                        updated_rows = []
                        for row in rows:
                            row_dict = dict(zip(columns, row))
                            row_dict['user_id'] = user_id
                            updated_rows.append([row_dict[col] for col in columns])
                        rows = updated_rows

                    # 构建插入语句
                    placeholders = ','.join(['?' for _ in columns])

                    if table_name == 'system_settings':
                        # 系统设置需要特殊处理，避免覆盖管理员密码
                        for row in rows:
                            if len(row) >= 1 and row[0] != 'admin_password_hash':
                                cursor.execute(f"INSERT INTO {table_name} ({','.join(columns)}) VALUES ({placeholders})", row)
                    else:
                        cursor.executemany(f"INSERT INTO {table_name} ({','.join(columns)}) VALUES ({placeholders})", rows)

                # 提交事务
                self.conn.commit()
                logger.info("导入备份成功")
                return True

            except Exception as e:
                logger.error(f"导入备份失败: {e}")
                self.conn.rollback()
                return False

    # -------------------- 系统设置操作 --------------------
    def get_system_setting(self, key: str) -> Optional[str]:
        """获取系统设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT value FROM system_settings WHERE key = ?", (key,))
                result = cursor.fetchone()
                return result[0] if result else None
            except Exception as e:
                logger.error(f"获取系统设置失败: {e}")
                return None

    def set_system_setting(self, key: str, value: str, description: str = None) -> bool:
        """设置系统设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO system_settings (key, value, description, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''', (key, value, description))
                self.conn.commit()
                logger.debug(f"设置系统设置: {key}")
                return True
            except Exception as e:
                logger.error(f"设置系统设置失败: {e}")
                self.conn.rollback()
                return False

    def get_all_system_settings(self) -> Dict[str, str]:
        """获取所有系统设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "SELECT key, value FROM system_settings")

                settings = {}
                for row in cursor.fetchall():
                    settings[row[0]] = row[1]

                return settings
            except Exception as e:
                logger.error(f"获取所有系统设置失败: {e}")
                return {}

    # 管理员密码现在统一使用用户表管理，不再需要单独的方法

    # ==================== 用户管理方法 ====================

    def create_user(self, username: str, email: str, password: str) -> bool:
        """创建新用户"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                password_hash = hashlib.sha256(password.encode()).hexdigest()

                cursor.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                ''', (username, email, password_hash))

                self.conn.commit()
                logger.info(f"创建用户成功: {username} ({email})")
                return True
            except sqlite3.IntegrityError as e:
                logger.error(f"创建用户失败，用户名或邮箱已存在: {e}")
                self.conn.rollback()
                return False
            except Exception as e:
                logger.error(f"创建用户失败: {e}")
                self.conn.rollback()
                return False

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """根据用户名获取用户信息"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 检查is_admin列是否存在
                cursor.execute("PRAGMA table_info(users)")
                columns = [col[1] for col in cursor.fetchall()]
                has_is_admin = 'is_admin' in columns

                if has_is_admin:
                    cursor.execute('''
                    SELECT id, username, email, password_hash, is_active, created_at, updated_at, is_admin
                    FROM users WHERE username = ?
                    ''', (username,))
                else:
                    cursor.execute('''
                    SELECT id, username, email, password_hash, is_active, created_at, updated_at
                    FROM users WHERE username = ?
                    ''', (username,))

                row = cursor.fetchone()
                if row:
                    user_data = {
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'password_hash': row[3],
                        'is_active': row[4],
                        'created_at': row[5],
                        'updated_at': row[6],
                    }
                    if has_is_admin:
                        user_data['is_admin'] = bool(row[7]) if row[7] is not None else (row[1] == 'admin')
                    else:
                        user_data['is_admin'] = (row[1] == 'admin')
                    return user_data
                return None
            except Exception as e:
                logger.error(f"获取用户信息失败: {e}")
                return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """根据邮箱获取用户信息"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 检查is_admin列是否存在
                cursor.execute("PRAGMA table_info(users)")
                columns = [col[1] for col in cursor.fetchall()]
                has_is_admin = 'is_admin' in columns

                if has_is_admin:
                    cursor.execute('''
                    SELECT id, username, email, password_hash, is_active, created_at, updated_at, is_admin
                    FROM users WHERE email = ?
                    ''', (email,))
                else:
                    cursor.execute('''
                    SELECT id, username, email, password_hash, is_active, created_at, updated_at
                    FROM users WHERE email = ?
                    ''', (email,))

                row = cursor.fetchone()
                if row:
                    user_data = {
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'password_hash': row[3],
                        'is_active': row[4],
                        'created_at': row[5],
                        'updated_at': row[6],
                    }
                    if has_is_admin:
                        user_data['is_admin'] = bool(row[7]) if row[7] is not None else (row[1] == 'admin')
                    else:
                        user_data['is_admin'] = (row[1] == 'admin')
                    return user_data
                return None
            except Exception as e:
                logger.error(f"获取用户信息失败: {e}")
                return None

    def verify_user_password(self, username: str, password: str) -> bool:
        """验证用户密码"""
        user = self.get_user_by_username(username)
        if not user:
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return user['password_hash'] == password_hash and user['is_active']

    def update_user_password(self, username: str, new_password: str) -> bool:
        """更新用户密码"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                password_hash = hashlib.sha256(new_password.encode()).hexdigest()

                cursor.execute('''
                UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                WHERE username = ?
                ''', (password_hash, username))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"用户 {username} 密码更新成功")
                    return True
                else:
                    logger.warning(f"用户 {username} 不存在，密码更新失败")
                    return False

            except Exception as e:
                logger.error(f"更新用户密码失败: {e}")
                self.conn.rollback()
                return False

    def generate_verification_code(self) -> str:
        """生成6位数字验证码"""
        return ''.join(random.choices(string.digits, k=6))

    def generate_captcha(self) -> Tuple[str, str]:
        """生成图形验证码
        返回: (验证码文本, base64编码的图片)
        """
        try:
            # 生成4位随机验证码（数字+字母）
            chars = string.ascii_uppercase + string.digits
            captcha_text = ''.join(random.choices(chars, k=4))

            # 创建图片
            width, height = 120, 40
            image = Image.new('RGB', (width, height), color='white')
            draw = ImageDraw.Draw(image)

            # 尝试使用系统字体，如果失败则使用默认字体
            try:
                # Windows系统字体
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                try:
                    # 备用字体
                    font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 20)
                except:
                    # 使用默认字体
                    font = ImageFont.load_default()

            # 绘制验证码文本
            for i, char in enumerate(captcha_text):
                # 随机颜色
                color = (
                    random.randint(0, 100),
                    random.randint(0, 100),
                    random.randint(0, 100)
                )

                # 随机位置（稍微偏移）
                x = 20 + i * 20 + random.randint(-3, 3)
                y = 8 + random.randint(-3, 3)

                draw.text((x, y), char, font=font, fill=color)

            # 添加干扰线
            for _ in range(3):
                start = (random.randint(0, width), random.randint(0, height))
                end = (random.randint(0, width), random.randint(0, height))
                draw.line([start, end], fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)), width=1)

            # 添加干扰点
            for _ in range(20):
                x = random.randint(0, width)
                y = random.randint(0, height)
                draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

            # 转换为base64
            buffer = io.BytesIO()
            image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()

            return captcha_text, f"data:image/png;base64,{img_base64}"

        except Exception as e:
            logger.error(f"生成图形验证码失败: {e}")
            # 返回简单的文本验证码作为备用
            simple_code = ''.join(random.choices(string.digits, k=4))
            return simple_code, ""

    def save_captcha(self, session_id: str, captcha_text: str, expires_minutes: int = 5) -> bool:
        """保存图形验证码"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                expires_at = time.time() + (expires_minutes * 60)

                # 删除该session的旧验证码
                cursor.execute('DELETE FROM captcha_codes WHERE session_id = ?', (session_id,))

                cursor.execute('''
                INSERT INTO captcha_codes (session_id, code, expires_at)
                VALUES (?, ?, ?)
                ''', (session_id, captcha_text.upper(), expires_at))

                self.conn.commit()
                logger.debug(f"保存图形验证码成功: {session_id}")
                return True
            except Exception as e:
                logger.error(f"保存图形验证码失败: {e}")
                self.conn.rollback()
                return False

    def verify_captcha(self, session_id: str, user_input: str) -> bool:
        """验证图形验证码"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                current_time = time.time()

                # 查找有效的验证码
                cursor.execute('''
                SELECT id FROM captcha_codes
                WHERE session_id = ? AND code = ? AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
                ''', (session_id, user_input.upper(), current_time))

                row = cursor.fetchone()
                if row:
                    # 删除已使用的验证码
                    cursor.execute('DELETE FROM captcha_codes WHERE id = ?', (row[0],))
                    self.conn.commit()
                    logger.debug(f"图形验证码验证成功: {session_id}")
                    return True
                else:
                    logger.warning(f"图形验证码验证失败: {session_id} - {user_input}")
                    return False
            except Exception as e:
                logger.error(f"验证图形验证码失败: {e}")
                return False

    def save_verification_code(self, email: str, code: str, code_type: str = 'register', expires_minutes: int = 10) -> bool:
        """保存邮箱验证码"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                expires_at = time.time() + (expires_minutes * 60)

                cursor.execute('''
                INSERT INTO email_verifications (email, code, type, expires_at)
                VALUES (?, ?, ?, ?)
                ''', (email, code, code_type, expires_at))

                self.conn.commit()
                logger.info(f"保存验证码成功: {email} ({code_type})")
                return True
            except Exception as e:
                logger.error(f"保存验证码失败: {e}")
                self.conn.rollback()
                return False

    def verify_email_code(self, email: str, code: str, code_type: str = 'register') -> bool:
        """验证邮箱验证码"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                current_time = time.time()

                # 查找有效的验证码
                cursor.execute('''
                SELECT id FROM email_verifications
                WHERE email = ? AND code = ? AND type = ? AND expires_at > ? AND used = FALSE
                ORDER BY created_at DESC LIMIT 1
                ''', (email, code, code_type, current_time))

                row = cursor.fetchone()
                if row:
                    # 标记验证码为已使用
                    cursor.execute('''
                    UPDATE email_verifications SET used = TRUE WHERE id = ?
                    ''', (row[0],))
                    self.conn.commit()
                    logger.info(f"验证码验证成功: {email} ({code_type})")
                    return True
                else:
                    logger.warning(f"验证码验证失败: {email} - {code} ({code_type})")
                    return False
            except Exception as e:
                logger.error(f"验证邮箱验证码失败: {e}")
                return False

    async def send_verification_email(self, email: str, code: str) -> bool:
        """发送验证码邮件（支持SMTP和API两种方式）"""
        try:
            subject = "闲鱼自动回复系统 - 邮箱验证码"
            # 使用简单的纯文本邮件内容
            text_content = f"""【闲鱼自动回复系统】邮箱验证码

您好！

感谢您使用闲鱼自动回复系统。为了确保账户安全，请使用以下验证码完成邮箱验证：

验证码：{code}

重要提醒：
• 验证码有效期为 10 分钟，请及时使用
• 请勿将验证码分享给任何人
• 如非本人操作，请忽略此邮件
• 系统不会主动索要您的验证码

如果您在使用过程中遇到任何问题，请联系我们的技术支持团队。
感谢您选择闲鱼自动回复系统！

---
此邮件由系统自动发送，请勿直接回复
© 2025 闲鱼自动回复系统"""

            # 从系统设置读取SMTP配置
            try:
                smtp_server = self.get_system_setting('smtp_server') or ''
                smtp_port = int(self.get_system_setting('smtp_port') or 0)
                smtp_user = self.get_system_setting('smtp_user') or ''
                smtp_password = self.get_system_setting('smtp_password') or ''
                smtp_from = (self.get_system_setting('smtp_from') or '').strip() or smtp_user
                smtp_use_tls = (self.get_system_setting('smtp_use_tls') or 'true').lower() == 'true'
                smtp_use_ssl = (self.get_system_setting('smtp_use_ssl') or 'false').lower() == 'true'
            except Exception as e:
                logger.error(f"读取SMTP系统设置失败: {e}")
                # 如果读取配置失败，使用API方式
                return await self._send_email_via_api(email, subject, text_content)

            # 检查SMTP配置是否完整
            if smtp_server and smtp_port and smtp_user and smtp_password:
                # 配置完整，使用SMTP方式发送
                logger.info(f"使用SMTP方式发送验证码邮件: {email}")
                return await self._send_email_via_smtp(email, subject, text_content,
                                                     smtp_server, smtp_port, smtp_user,
                                                     smtp_password, smtp_from, smtp_use_tls, smtp_use_ssl)
            else:
                # 配置不完整，使用API方式发送
                logger.info(f"SMTP配置不完整，使用API方式发送验证码邮件: {email}")
                return await self._send_email_via_api(email, subject, text_content)

        except Exception as e:
            logger.error(f"发送验证码邮件异常: {e}")
            return False

    async def _send_email_via_smtp(self, email: str, subject: str, text_content: str,
                                 smtp_server: str, smtp_port: int, smtp_user: str,
                                 smtp_password: str, smtp_from: str, smtp_use_tls: bool, smtp_use_ssl: bool) -> bool:
        """使用SMTP方式发送邮件"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = smtp_from
            msg['To'] = email

            msg.attach(MIMEText(text_content, 'plain', 'utf-8'))

            if smtp_use_ssl:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port)

            server.ehlo()
            if smtp_use_tls and not smtp_use_ssl:
                server.starttls()
                server.ehlo()

            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, [email], msg.as_string())
            server.quit()

            logger.info(f"验证码邮件发送成功(SMTP): {email}")
            return True
        except Exception as e:
            logger.error(f"SMTP发送验证码邮件失败: {e}")
            # SMTP发送失败，尝试使用API方式
            logger.info(f"SMTP发送失败，尝试使用API方式发送: {email}")
            return await self._send_email_via_api(email, subject, text_content)

    async def _send_email_via_api(self, email: str, subject: str, text_content: str) -> bool:
        """使用API方式发送邮件"""
        try:
            import aiohttp

            # 使用GET请求发送邮件
            api_url = "https://dy.zhinianboke.com/api/emailSend"
            params = {
                'subject': subject,
                'receiveUser': email,
                'sendHtml': text_content
            }

            async with aiohttp.ClientSession() as session:
                try:
                    logger.info(f"使用API发送验证码邮件: {email}")
                    async with session.get(api_url, params=params, timeout=15) as response:
                        response_text = await response.text()
                        logger.info(f"邮件API响应: {response.status}")

                        if response.status == 200:
                            logger.info(f"验证码邮件发送成功(API): {email}")
                            return True
                        else:
                            logger.error(f"API发送验证码邮件失败: {email}, 状态码: {response.status}, 响应: {response_text[:200]}")
                            return False
                except Exception as e:
                    logger.error(f"API邮件发送异常: {email}, 错误: {e}")
                    return False
        except Exception as e:
            logger.error(f"API邮件发送方法异常: {e}")
            return False

    # ==================== 卡券管理方法 ====================

    def create_card(self, name: str, card_type: str, api_config=None,
                   text_content: str = None, data_content: str = None, image_url: str = None,
                   description: str = None, enabled: bool = True, delay_seconds: int = 0,
                   is_multi_spec: bool = False, spec_name: str = None, spec_value: str = None,
                   spec_name_2: str = None, spec_value_2: str = None, user_id: int = None):
        """创建新卡券（支持双规格）"""
        # 调试日志
        logger.info(f"[DEBUG DB] create_card 被调用 - name: {name}")
        logger.info(f"[DEBUG DB] is_multi_spec: {is_multi_spec}, type: {type(is_multi_spec)}")
        logger.info(f"[DEBUG DB] spec_name: {spec_name}, spec_value: {spec_value}")
        logger.info(f"[DEBUG DB] spec_name_2: {spec_name_2}, type: {type(spec_name_2)}")
        logger.info(f"[DEBUG DB] spec_value_2: {spec_value_2}, type: {type(spec_value_2)}")

        with self.lock:
            try:
                # 验证多规格参数
                if is_multi_spec:
                    if not spec_name or not spec_value:
                        raise ValueError("多规格卡券必须提供规格名称和规格值")

                    # 检查唯一性：卡券名称+规格名称+规格值
                    cursor = self.conn.cursor()
                    cursor.execute('''
                    SELECT COUNT(*) FROM cards
                    WHERE name = ? AND spec_name = ? AND spec_value = ? AND user_id = ?
                    ''', (name, spec_name, spec_value, user_id))

                    if cursor.fetchone()[0] > 0:
                        raise ValueError(f"卡券已存在：{name} - {spec_name}:{spec_value}")
                else:
                    # 检查唯一性：仅卡券名称
                    cursor = self.conn.cursor()
                    cursor.execute('''
                    SELECT COUNT(*) FROM cards
                    WHERE name = ? AND (is_multi_spec = 0 OR is_multi_spec IS NULL) AND user_id = ?
                    ''', (name, user_id))

                    if cursor.fetchone()[0] > 0:
                        raise ValueError(f"卡券名称已存在：{name}")

                # 处理api_config参数 - 如果是字典则转换为JSON字符串
                api_config_str = None
                if api_config is not None:
                    if isinstance(api_config, dict):
                        import json
                        api_config_str = json.dumps(api_config)
                    else:
                        api_config_str = str(api_config)

                cursor.execute('''
                INSERT INTO cards (name, type, api_config, text_content, data_content, image_url,
                                 description, enabled, delay_seconds, is_multi_spec,
                                 spec_name, spec_value, spec_name_2, spec_value_2, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, card_type, api_config_str, text_content, data_content, image_url,
                      description, enabled, delay_seconds, is_multi_spec,
                      spec_name, spec_value, spec_name_2, spec_value_2, user_id))
                self.conn.commit()
                card_id = cursor.lastrowid

                if is_multi_spec:
                    logger.info(f"创建多规格卡券成功: {name} - {spec_name}:{spec_value} (ID: {card_id})")
                else:
                    logger.info(f"创建卡券成功: {name} (ID: {card_id})")
                return card_id
            except Exception as e:
                logger.error(f"创建卡券失败: {e}")
                raise

    def get_all_cards(self, user_id: int = None):
        """获取所有卡券（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    cursor.execute('''
                    SELECT id, name, type, api_config, text_content, data_content, image_url,
                           description, enabled, delay_seconds, is_multi_spec,
                           spec_name, spec_value, spec_name_2, spec_value_2, created_at, updated_at
                    FROM cards
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    ''', (user_id,))
                else:
                    cursor.execute('''
                    SELECT id, name, type, api_config, text_content, data_content, image_url,
                           description, enabled, delay_seconds, is_multi_spec,
                           spec_name, spec_value, spec_name_2, spec_value_2, created_at, updated_at
                    FROM cards
                    ORDER BY created_at DESC
                    ''')

                cards = []
                for row in cursor.fetchall():
                    # 解析api_config JSON字符串
                    api_config = row[3]
                    if api_config:
                        try:
                            import json
                            api_config = json.loads(api_config)
                        except (json.JSONDecodeError, TypeError):
                            # 如果解析失败，保持原始字符串
                            pass

                    cards.append({
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'api_config': api_config,
                        'text_content': row[4],
                        'data_content': row[5],
                        'image_url': row[6],
                        'description': row[7],
                        'enabled': bool(row[8]),
                        'delay_seconds': row[9] or 0,
                        'is_multi_spec': bool(row[10]) if row[10] is not None else False,
                        'spec_name': row[11],
                        'spec_value': row[12],
                        'spec_name_2': row[13],
                        'spec_value_2': row[14],
                        'created_at': row[15],
                        'updated_at': row[16]
                    })

                return cards
            except Exception as e:
                logger.error(f"获取卡券列表失败: {e}")
                return []

    def get_card_by_id(self, card_id: int, user_id: int = None):
        """根据ID获取卡券（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    cursor.execute('''
                    SELECT id, name, type, api_config, text_content, data_content, image_url,
                           description, enabled, delay_seconds, is_multi_spec,
                           spec_name, spec_value, spec_name_2, spec_value_2, created_at, updated_at
                    FROM cards WHERE id = ? AND user_id = ?
                    ''', (card_id, user_id))
                else:
                    cursor.execute('''
                    SELECT id, name, type, api_config, text_content, data_content, image_url,
                           description, enabled, delay_seconds, is_multi_spec,
                           spec_name, spec_value, spec_name_2, spec_value_2, created_at, updated_at
                    FROM cards WHERE id = ?
                    ''', (card_id,))

                row = cursor.fetchone()
                if row:
                    # 解析api_config JSON字符串
                    api_config = row[3]
                    if api_config:
                        try:
                            import json
                            api_config = json.loads(api_config)
                        except (json.JSONDecodeError, TypeError):
                            # 如果解析失败，保持原始字符串
                            pass

                    return {
                        'id': row[0],
                        'name': row[1],
                        'type': row[2],
                        'api_config': api_config,
                        'text_content': row[4],
                        'data_content': row[5],
                        'image_url': row[6],
                        'description': row[7],
                        'enabled': bool(row[8]),
                        'delay_seconds': row[9] or 0,
                        'is_multi_spec': bool(row[10]) if row[10] is not None else False,
                        'spec_name': row[11],
                        'spec_value': row[12],
                        'spec_name_2': row[13],
                        'spec_value_2': row[14],
                        'created_at': row[15],
                        'updated_at': row[16]
                    }
                return None
            except Exception as e:
                logger.error(f"获取卡券失败: {e}")
                return None

    def update_card(self, card_id: int, name: str = None, card_type: str = None,
                   api_config=None, text_content: str = None, data_content: str = None,
                   image_url: str = None, description: str = None, enabled: bool = None,
                   delay_seconds: int = None, is_multi_spec: bool = None, spec_name: str = None,
                   spec_value: str = None, spec_name_2: str = None, spec_value_2: str = None):
        """更新卡券"""
        # 调试日志
        logger.info(f"[DEBUG DB] update_card 被调用 - card_id: {card_id}")
        logger.info(f"[DEBUG DB] is_multi_spec: {is_multi_spec}, type: {type(is_multi_spec)}")
        logger.info(f"[DEBUG DB] spec_name: {spec_name}, spec_value: {spec_value}")
        logger.info(f"[DEBUG DB] spec_name_2: {spec_name_2}, type: {type(spec_name_2)}")
        logger.info(f"[DEBUG DB] spec_value_2: {spec_value_2}, type: {type(spec_value_2)}")

        with self.lock:
            try:
                # 处理api_config参数
                api_config_str = None
                if api_config is not None:
                    if isinstance(api_config, dict):
                        import json
                        api_config_str = json.dumps(api_config)
                    else:
                        api_config_str = str(api_config)

                cursor = self.conn.cursor()

                # 构建更新语句
                update_fields = []
                params = []

                if name is not None:
                    update_fields.append("name = ?")
                    params.append(name)
                if card_type is not None:
                    update_fields.append("type = ?")
                    params.append(card_type)
                if api_config_str is not None:
                    update_fields.append("api_config = ?")
                    params.append(api_config_str)
                if text_content is not None:
                    update_fields.append("text_content = ?")
                    params.append(text_content)
                if data_content is not None:
                    update_fields.append("data_content = ?")
                    params.append(data_content)
                if image_url is not None:
                    update_fields.append("image_url = ?")
                    params.append(image_url)
                if description is not None:
                    update_fields.append("description = ?")
                    params.append(description)
                if enabled is not None:
                    update_fields.append("enabled = ?")
                    params.append(enabled)
                if delay_seconds is not None:
                    update_fields.append("delay_seconds = ?")
                    params.append(delay_seconds)
                if is_multi_spec is not None:
                    update_fields.append("is_multi_spec = ?")
                    params.append(is_multi_spec)
                if spec_name is not None:
                    update_fields.append("spec_name = ?")
                    params.append(spec_name)
                if spec_value is not None:
                    update_fields.append("spec_value = ?")
                    params.append(spec_value)
                if spec_name_2 is not None:
                    update_fields.append("spec_name_2 = ?")
                    params.append(spec_name_2)
                if spec_value_2 is not None:
                    update_fields.append("spec_value_2 = ?")
                    params.append(spec_value_2)

                if not update_fields:
                    return True  # 没有需要更新的字段

                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                params.append(card_id)

                sql = f"UPDATE cards SET {', '.join(update_fields)} WHERE id = ?"
                logger.info(f"[DEBUG DB] 执行SQL: {sql}")
                logger.info(f"[DEBUG DB] 参数: {params}")
                self._execute_sql(cursor, sql, params)

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"更新卡券成功: ID {card_id}")
                    return True
                else:
                    return False  # 没有找到对应的记录

            except Exception as e:
                logger.error(f"更新卡券失败: {e}")
                self.conn.rollback()
                raise

    def update_card_image_url(self, card_id: int, new_image_url: str) -> bool:
        """更新卡券的图片URL"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 更新图片URL
                self._execute_sql(cursor,
                    "UPDATE cards SET image_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND type = 'image'",
                    (new_image_url, card_id))

                self.conn.commit()

                # 检查是否有行被更新
                if cursor.rowcount > 0:
                    logger.info(f"卡券图片URL更新成功: 卡券ID: {card_id}, 新URL: {new_image_url}")
                    return True
                else:
                    logger.warning(f"未找到匹配的图片卡券: 卡券ID: {card_id}")
                    return False

            except Exception as e:
                logger.error(f"更新卡券图片URL失败: {e}")
                self.conn.rollback()
                return False

    # ==================== 自动发货规则方法 ====================

    def create_delivery_rule(self, keyword: str, card_id: int, delivery_count: int = 1,
                           enabled: bool = True, description: str = None, user_id: int = None):
        """创建发货规则"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT INTO delivery_rules (keyword, card_id, delivery_count, enabled, description, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (keyword, card_id, delivery_count, enabled, description, user_id))
                self.conn.commit()
                rule_id = cursor.lastrowid
                logger.info(f"创建发货规则成功: {keyword} -> 卡券ID {card_id} (规则ID: {rule_id})")
                return rule_id
            except Exception as e:
                logger.error(f"创建发货规则失败: {e}")
                raise

    def get_all_delivery_rules(self, user_id: int = None):
        """获取所有发货规则"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    cursor.execute('''
                    SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                           dr.description, dr.delivery_times, dr.created_at, dr.updated_at,
                           c.name as card_name, c.type as card_type,
                           c.is_multi_spec, c.spec_name, c.spec_value,
                           c.spec_name_2, c.spec_value_2
                    FROM delivery_rules dr
                    LEFT JOIN cards c ON dr.card_id = c.id
                    WHERE dr.user_id = ?
                    ORDER BY dr.created_at DESC
                    ''', (user_id,))
                else:
                    cursor.execute('''
                    SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                           dr.description, dr.delivery_times, dr.created_at, dr.updated_at,
                           c.name as card_name, c.type as card_type,
                           c.is_multi_spec, c.spec_name, c.spec_value,
                           c.spec_name_2, c.spec_value_2
                    FROM delivery_rules dr
                    LEFT JOIN cards c ON dr.card_id = c.id
                    ORDER BY dr.created_at DESC
                    ''')

                rules = []
                for row in cursor.fetchall():
                    rules.append({
                        'id': row[0],
                        'keyword': row[1],
                        'card_id': row[2],
                        'delivery_count': row[3],
                        'enabled': bool(row[4]),
                        'description': row[5],
                        'delivery_times': row[6],
                        'created_at': row[7],
                        'updated_at': row[8],
                        'card_name': row[9],
                        'card_type': row[10],
                        'is_multi_spec': bool(row[11]) if row[11] is not None else False,
                        'spec_name': row[12],
                        'spec_value': row[13],
                        'spec_name_2': row[14],
                        'spec_value_2': row[15]
                    })

                return rules
            except Exception as e:
                logger.error(f"获取发货规则列表失败: {e}")
                return []

    def get_delivery_rules_by_keyword(self, keyword: str, user_id: int = None):
        """根据关键字获取匹配的发货规则

        Args:
            keyword: 搜索关键字（商品标题）
            user_id: 用户ID，用于过滤只属于该用户的发货规则
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 使用更灵活的匹配方式：既支持商品内容包含关键字，也支持关键字包含在商品内容中
                if user_id is not None:
                    cursor.execute('''
                    SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                           dr.description, dr.delivery_times,
                           c.name as card_name, c.type as card_type, c.api_config,
                           c.text_content, c.data_content, c.image_url, c.enabled as card_enabled, c.description as card_description,
                           c.delay_seconds as card_delay_seconds
                    FROM delivery_rules dr
                    LEFT JOIN cards c ON dr.card_id = c.id
                    WHERE dr.enabled = 1 AND c.enabled = 1 AND dr.user_id = ?
                    AND (? LIKE '%' || dr.keyword || '%' OR dr.keyword LIKE '%' || ? || '%')
                    ORDER BY
                        CASE
                            WHEN ? LIKE '%' || dr.keyword || '%' THEN LENGTH(dr.keyword)
                            ELSE LENGTH(dr.keyword) / 2
                        END DESC,
                        dr.id ASC
                    ''', (user_id, keyword, keyword, keyword))
                else:
                    cursor.execute('''
                    SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                           dr.description, dr.delivery_times,
                           c.name as card_name, c.type as card_type, c.api_config,
                           c.text_content, c.data_content, c.image_url, c.enabled as card_enabled, c.description as card_description,
                           c.delay_seconds as card_delay_seconds
                    FROM delivery_rules dr
                    LEFT JOIN cards c ON dr.card_id = c.id
                    WHERE dr.enabled = 1 AND c.enabled = 1
                    AND (? LIKE '%' || dr.keyword || '%' OR dr.keyword LIKE '%' || ? || '%')
                    ORDER BY
                        CASE
                            WHEN ? LIKE '%' || dr.keyword || '%' THEN LENGTH(dr.keyword)
                            ELSE LENGTH(dr.keyword) / 2
                        END DESC,
                        dr.id ASC
                    ''', (keyword, keyword, keyword))

                rules = []
                for row in cursor.fetchall():
                    # 解析api_config JSON字符串
                    api_config = row[9]
                    if api_config:
                        try:
                            import json
                            api_config = json.loads(api_config)
                        except (json.JSONDecodeError, TypeError):
                            # 如果解析失败，保持原始字符串
                            pass

                    rules.append({
                        'id': row[0],
                        'keyword': row[1],
                        'card_id': row[2],
                        'delivery_count': row[3],
                        'enabled': bool(row[4]),
                        'description': row[5],
                        'delivery_times': row[6],
                        'card_name': row[7],
                        'card_type': row[8],
                        'api_config': api_config,  # 修复字段名
                        'text_content': row[10],
                        'data_content': row[11],
                        'image_url': row[12],
                        'card_enabled': bool(row[13]),
                        'card_description': row[14],  # 卡券备注信息
                        'card_delay_seconds': row[15] or 0  # 延时秒数
                    })

                return rules
            except Exception as e:
                logger.error(f"根据关键字获取发货规则失败: {e}")
                return []

    def get_delivery_rule_by_id(self, rule_id: int, user_id: int = None):
        """根据ID获取发货规则（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    self._execute_sql(cursor, '''
                    SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                           dr.description, dr.delivery_times, dr.created_at, dr.updated_at,
                           c.name as card_name, c.type as card_type,
                           c.is_multi_spec, c.spec_name, c.spec_value,
                           c.spec_name_2, c.spec_value_2
                    FROM delivery_rules dr
                    LEFT JOIN cards c ON dr.card_id = c.id
                    WHERE dr.id = ? AND dr.user_id = ?
                    ''', (rule_id, user_id))
                else:
                    self._execute_sql(cursor, '''
                    SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                           dr.description, dr.delivery_times, dr.created_at, dr.updated_at,
                           c.name as card_name, c.type as card_type,
                           c.is_multi_spec, c.spec_name, c.spec_value,
                           c.spec_name_2, c.spec_value_2
                    FROM delivery_rules dr
                    LEFT JOIN cards c ON dr.card_id = c.id
                    WHERE dr.id = ?
                    ''', (rule_id,))

                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'keyword': row[1],
                        'card_id': row[2],
                        'delivery_count': row[3],
                        'enabled': bool(row[4]),
                        'description': row[5],
                        'delivery_times': row[6],
                        'created_at': row[7],
                        'updated_at': row[8],
                        'card_name': row[9],
                        'card_type': row[10],
                        'is_multi_spec': bool(row[11]) if row[11] is not None else False,
                        'spec_name': row[12],
                        'spec_value': row[13],
                        'spec_name_2': row[14],
                        'spec_value_2': row[15]
                    }
                return None
            except Exception as e:
                logger.error(f"获取发货规则失败: {e}")
                return None

    def update_delivery_rule(self, rule_id: int, keyword: str = None, card_id: int = None,
                           delivery_count: int = None, enabled: bool = None,
                           description: str = None, user_id: int = None):
        """更新发货规则（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 构建更新语句
                update_fields = []
                params = []

                if keyword is not None:
                    update_fields.append("keyword = ?")
                    params.append(keyword)
                if card_id is not None:
                    update_fields.append("card_id = ?")
                    params.append(card_id)
                if delivery_count is not None:
                    update_fields.append("delivery_count = ?")
                    params.append(delivery_count)
                if enabled is not None:
                    update_fields.append("enabled = ?")
                    params.append(enabled)
                if description is not None:
                    update_fields.append("description = ?")
                    params.append(description)

                if not update_fields:
                    return True  # 没有需要更新的字段

                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                params.append(rule_id)

                if user_id is not None:
                    params.append(user_id)
                    sql = f"UPDATE delivery_rules SET {', '.join(update_fields)} WHERE id = ? AND user_id = ?"
                else:
                    sql = f"UPDATE delivery_rules SET {', '.join(update_fields)} WHERE id = ?"

                self._execute_sql(cursor, sql, params)

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"更新发货规则成功: ID {rule_id}")
                    return True
                else:
                    return False  # 没有找到对应的记录

            except Exception as e:
                logger.error(f"更新发货规则失败: {e}")
                self.conn.rollback()
                raise

    def increment_delivery_times(self, rule_id: int):
        """增加发货次数（同时更新今日发货次数）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                today = datetime.now().strftime('%Y-%m-%d')

                # 先查询当前规则的最后发货日期
                cursor.execute('SELECT last_delivery_date FROM delivery_rules WHERE id = ?', (rule_id,))
                row = cursor.fetchone()
                last_date = row[0] if row else None

                if last_date == today:
                    # 今天已有发货记录，增加今日发货次数
                    cursor.execute('''
                    UPDATE delivery_rules
                    SET delivery_times = delivery_times + 1,
                        today_delivery_times = today_delivery_times + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    ''', (rule_id,))
                else:
                    # 新的一天，重置今日发货次数为1
                    cursor.execute('''
                    UPDATE delivery_rules
                    SET delivery_times = delivery_times + 1,
                        last_delivery_date = ?,
                        today_delivery_times = 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    ''', (today, rule_id))

                self.conn.commit()
                logger.debug(f"发货规则 {rule_id} 发货次数已增加")
            except Exception as e:
                logger.error(f"更新发货次数失败: {e}")

    def get_today_delivery_count(self, user_id: int = None):
        """获取今日发货总数"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                today = datetime.now().strftime('%Y-%m-%d')

                if user_id is not None:
                    cursor.execute('''
                    SELECT COALESCE(SUM(today_delivery_times), 0)
                    FROM delivery_rules
                    WHERE last_delivery_date = ? AND user_id = ?
                    ''', (today, user_id))
                else:
                    cursor.execute('''
                    SELECT COALESCE(SUM(today_delivery_times), 0)
                    FROM delivery_rules
                    WHERE last_delivery_date = ?
                    ''', (today,))

                row = cursor.fetchone()
                return row[0] if row else 0
            except Exception as e:
                logger.error(f"获取今日发货统计失败: {e}")
                return 0

    def get_delivery_rules_by_keyword_and_spec(self, keyword: str, spec_name: str = None, spec_value: str = None,
                                               spec_name_2: str = None, spec_value_2: str = None, user_id: int = None):
        """根据关键字和规格信息获取匹配的发货规则（支持双规格）

        Args:
            keyword: 搜索关键字（商品标题）
            spec_name: 规格1名称
            spec_value: 规格1值
            spec_name_2: 规格2名称
            spec_value_2: 规格2值
            user_id: 用户ID，用于过滤只属于该用户的发货规则
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 构建user_id过滤条件
                user_filter = "AND dr.user_id = ?" if user_id is not None else ""

                # 优先匹配：卡券名称+规格1+规格2（如果都有的话）
                if spec_name and spec_value:
                    # 构建匹配条件：规格1必须匹配，规格2如果订单有则必须匹配，如果订单没有则卡券也不能有
                    if spec_name_2 and spec_value_2:
                        # 订单有双规格，卡券也必须有双规格且都匹配
                        sql = f'''
                        SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                               dr.description, dr.delivery_times,
                               c.name as card_name, c.type as card_type, c.api_config,
                               c.text_content, c.data_content, c.enabled as card_enabled,
                               c.description as card_description, c.delay_seconds as card_delay_seconds,
                               c.is_multi_spec, c.spec_name, c.spec_value, c.spec_name_2, c.spec_value_2
                        FROM delivery_rules dr
                        LEFT JOIN cards c ON dr.card_id = c.id
                        WHERE dr.enabled = 1 AND c.enabled = 1 {user_filter}
                        AND (? LIKE '%' || dr.keyword || '%' OR dr.keyword LIKE '%' || ? || '%')
                        AND c.is_multi_spec = 1 AND c.spec_name = ? AND c.spec_value = ?
                        AND c.spec_name_2 = ? AND c.spec_value_2 = ?
                        ORDER BY
                            CASE
                                WHEN ? LIKE '%' || dr.keyword || '%' THEN LENGTH(dr.keyword)
                                ELSE LENGTH(dr.keyword) / 2
                            END DESC,
                            dr.delivery_times ASC
                        '''
                        params = [user_id, keyword, keyword, spec_name, spec_value, spec_name_2, spec_value_2, keyword] if user_id is not None else [keyword, keyword, spec_name, spec_value, spec_name_2, spec_value_2, keyword]
                        cursor.execute(sql, [p for p in params if p is not None or user_id is None])
                    else:
                        # 订单只有单规格，优先匹配只有单规格的卡券
                        sql = f'''
                        SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                               dr.description, dr.delivery_times,
                               c.name as card_name, c.type as card_type, c.api_config,
                               c.text_content, c.data_content, c.enabled as card_enabled,
                               c.description as card_description, c.delay_seconds as card_delay_seconds,
                               c.is_multi_spec, c.spec_name, c.spec_value, c.spec_name_2, c.spec_value_2
                        FROM delivery_rules dr
                        LEFT JOIN cards c ON dr.card_id = c.id
                        WHERE dr.enabled = 1 AND c.enabled = 1 {user_filter}
                        AND (? LIKE '%' || dr.keyword || '%' OR dr.keyword LIKE '%' || ? || '%')
                        AND c.is_multi_spec = 1 AND c.spec_name = ? AND c.spec_value = ?
                        AND (c.spec_name_2 IS NULL OR c.spec_name_2 = '')
                        ORDER BY
                            CASE
                                WHEN ? LIKE '%' || dr.keyword || '%' THEN LENGTH(dr.keyword)
                                ELSE LENGTH(dr.keyword) / 2
                            END DESC,
                            dr.delivery_times ASC
                        '''
                        params = [user_id, keyword, keyword, spec_name, spec_value, keyword] if user_id is not None else [keyword, keyword, spec_name, spec_value, keyword]
                        cursor.execute(sql, [p for p in params if p is not None or user_id is None])

                    rules = []
                    for row in cursor.fetchall():
                        # 解析api_config JSON字符串
                        api_config = row[9]
                        if api_config:
                            try:
                                import json
                                api_config = json.loads(api_config)
                            except (json.JSONDecodeError, TypeError):
                                # 如果解析失败，保持原始字符串
                                pass

                        rules.append({
                            'id': row[0],
                            'keyword': row[1],
                            'card_id': row[2],
                            'delivery_count': row[3],
                            'enabled': bool(row[4]),
                            'description': row[5],
                            'delivery_times': row[6] or 0,
                            'card_name': row[7],
                            'card_type': row[8],
                            'api_config': api_config,
                            'text_content': row[10],
                            'data_content': row[11],
                            'card_enabled': bool(row[12]),
                            'card_description': row[13],
                            'card_delay_seconds': row[14] or 0,
                            'is_multi_spec': bool(row[15]),
                            'spec_name': row[16],
                            'spec_value': row[17],
                            'spec_name_2': row[18],
                            'spec_value_2': row[19]
                        })

                    if rules:
                        if spec_name_2 and spec_value_2:
                            logger.info(f"找到双规格匹配规则: {keyword} - {spec_name}:{spec_value}, {spec_name_2}:{spec_value_2}")
                        else:
                            logger.info(f"找到单规格匹配规则: {keyword} - {spec_name}:{spec_value}")
                        return rules

                # 兜底匹配：仅卡券名称
                cursor.execute('''
                SELECT dr.id, dr.keyword, dr.card_id, dr.delivery_count, dr.enabled,
                       dr.description, dr.delivery_times,
                       c.name as card_name, c.type as card_type, c.api_config,
                       c.text_content, c.data_content, c.enabled as card_enabled,
                       c.description as card_description, c.delay_seconds as card_delay_seconds,
                       c.is_multi_spec, c.spec_name, c.spec_value, c.spec_name_2, c.spec_value_2
                FROM delivery_rules dr
                LEFT JOIN cards c ON dr.card_id = c.id
                WHERE dr.enabled = 1 AND c.enabled = 1
                AND (? LIKE '%' || dr.keyword || '%' OR dr.keyword LIKE '%' || ? || '%')
                AND (c.is_multi_spec = 0 OR c.is_multi_spec IS NULL)
                ORDER BY
                    CASE
                        WHEN ? LIKE '%' || dr.keyword || '%' THEN LENGTH(dr.keyword)
                        ELSE LENGTH(dr.keyword) / 2
                    END DESC,
                    dr.delivery_times ASC
                ''', (keyword, keyword, keyword))

                rules = []
                for row in cursor.fetchall():
                    # 解析api_config JSON字符串
                    api_config = row[9]
                    if api_config:
                        try:
                            import json
                            api_config = json.loads(api_config)
                        except (json.JSONDecodeError, TypeError):
                            # 如果解析失败，保持原始字符串
                            pass

                    rules.append({
                        'id': row[0],
                        'keyword': row[1],
                        'card_id': row[2],
                        'delivery_count': row[3],
                        'enabled': bool(row[4]),
                        'description': row[5],
                        'delivery_times': row[6] or 0,
                        'card_name': row[7],
                        'card_type': row[8],
                        'api_config': api_config,
                        'text_content': row[10],
                        'data_content': row[11],
                        'card_enabled': bool(row[12]),
                        'card_description': row[13],
                        'card_delay_seconds': row[14] or 0,
                        'is_multi_spec': bool(row[15]) if row[15] is not None else False,
                        'spec_name': row[16],
                        'spec_value': row[17],
                        'spec_name_2': row[18],
                        'spec_value_2': row[19]
                    })

                if rules:
                    logger.info(f"找到兜底匹配规则: {keyword}")
                else:
                    logger.info(f"未找到匹配规则: {keyword}")

                return rules

            except Exception as e:
                logger.error(f"获取发货规则失败: {e}")
                return []

    def delete_card(self, card_id: int):
        """删除卡券"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                self._execute_sql(cursor, "DELETE FROM cards WHERE id = ?", (card_id,))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"删除卡券成功: ID {card_id}")
                    return True
                else:
                    return False  # 没有找到对应的记录

            except Exception as e:
                logger.error(f"删除卡券失败: {e}")
                self.conn.rollback()
                raise

    def delete_delivery_rule(self, rule_id: int, user_id: int = None):
        """删除发货规则（支持用户隔离）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                if user_id is not None:
                    self._execute_sql(cursor, "DELETE FROM delivery_rules WHERE id = ? AND user_id = ?", (rule_id, user_id))
                else:
                    self._execute_sql(cursor, "DELETE FROM delivery_rules WHERE id = ?", (rule_id,))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"删除发货规则成功: ID {rule_id} (用户ID: {user_id})")
                    return True
                else:
                    return False  # 没有找到对应的记录

            except Exception as e:
                logger.error(f"删除发货规则失败: {e}")
                self.conn.rollback()
                raise

    def consume_batch_data(self, card_id: int):
        """消费批量数据的第一条记录（线程安全）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 获取卡券的批量数据
                self._execute_sql(cursor, "SELECT data_content FROM cards WHERE id = ? AND type = 'data'", (card_id,))
                result = cursor.fetchone()

                if not result or not result[0]:
                    logger.warning(f"卡券 {card_id} 没有批量数据")
                    return None

                data_content = result[0]
                lines = [line.strip() for line in data_content.split('\n') if line.strip()]

                if not lines:
                    logger.warning(f"卡券 {card_id} 批量数据为空")
                    return None

                # 获取第一条数据
                first_line = lines[0]

                # 移除第一条数据，更新数据库
                remaining_lines = lines[1:]
                new_data_content = '\n'.join(remaining_lines)

                cursor.execute('''
                UPDATE cards
                SET data_content = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''', (new_data_content, card_id))

                self.conn.commit()

                logger.info(f"消费批量数据成功: 卡券ID={card_id}, 剩余={len(remaining_lines)}条")
                return first_line

            except Exception as e:
                logger.error(f"消费批量数据失败: {e}")
                self.conn.rollback()
                return None

    # ==================== 商品信息管理 ====================

    def save_item_basic_info(self, cookie_id: str, item_id: str, item_title: str = None,
                            item_description: str = None, item_category: str = None,
                            item_price: str = None, item_detail: str = None) -> bool:
        """保存或更新商品基本信息，使用原子操作避免并发问题

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID
            item_title: 商品标题
            item_description: 商品描述
            item_category: 商品分类
            item_price: 商品价格
            item_detail: 商品详情JSON

        Returns:
            bool: 操作是否成功
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()

                # 使用 INSERT OR IGNORE + UPDATE 的原子操作模式
                # 首先尝试插入，如果已存在则忽略
                cursor.execute('''
                INSERT OR IGNORE INTO item_info (cookie_id, item_id, item_title, item_description,
                                               item_category, item_price, item_detail, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (cookie_id, item_id, item_title or '', item_description or '',
                      item_category or '', item_price or '', item_detail or ''))

                # 如果是新插入的记录，直接返回成功
                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"新增商品基本信息: {item_id} - {item_title}")
                    return True

                # 记录已存在，使用原子UPDATE操作，只更新非空字段且不覆盖现有非空值
                update_parts = []
                params = []

                # 使用 CASE WHEN 语句进行条件更新，避免覆盖现有数据
                if item_title:
                    update_parts.append("item_title = CASE WHEN (item_title IS NULL OR item_title = '') THEN ? ELSE item_title END")
                    params.append(item_title)

                if item_description:
                    update_parts.append("item_description = CASE WHEN (item_description IS NULL OR item_description = '') THEN ? ELSE item_description END")
                    params.append(item_description)

                if item_category:
                    update_parts.append("item_category = CASE WHEN (item_category IS NULL OR item_category = '') THEN ? ELSE item_category END")
                    params.append(item_category)

                if item_price:
                    update_parts.append("item_price = CASE WHEN (item_price IS NULL OR item_price = '') THEN ? ELSE item_price END")
                    params.append(item_price)

                # 对于item_detail，只有在现有值为空时才更新
                if item_detail:
                    update_parts.append("item_detail = CASE WHEN (item_detail IS NULL OR item_detail = '' OR TRIM(item_detail) = '') THEN ? ELSE item_detail END")
                    params.append(item_detail)

                if update_parts:
                    update_parts.append("updated_at = CURRENT_TIMESTAMP")
                    params.extend([cookie_id, item_id])

                    sql = f"UPDATE item_info SET {', '.join(update_parts)} WHERE cookie_id = ? AND item_id = ?"
                    self._execute_sql(cursor, sql, params)

                    if cursor.rowcount > 0:
                        logger.info(f"更新商品基本信息: {item_id} - {item_title}")
                    else:
                        logger.debug(f"商品信息无需更新: {item_id}")

                self.conn.commit()
                return True

        except Exception as e:
            logger.error(f"保存商品基本信息失败: {e}")
            self.conn.rollback()
            return False

    def save_item_info(self, cookie_id: str, item_id: str, item_data = None) -> bool:
        """保存或更新商品信息

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID
            item_data: 商品详情数据，可以是字符串或字典，也可以为None

        Returns:
            bool: 操作是否成功
        """
        try:
            # 验证：如果只有商品ID，没有商品详情数据，则不插入数据库
            if not item_data:
                logger.debug(f"跳过保存商品信息：缺少商品详情数据 - {item_id}")
                return False

            # 如果是字典类型，检查是否有标题信息
            if isinstance(item_data, dict):
                title = item_data.get('title', '').strip()
                if not title:
                    logger.debug(f"跳过保存商品信息：缺少商品标题 - {item_id}")
                    return False

            # 如果是字符串类型，检查是否为空
            if isinstance(item_data, str) and not item_data.strip():
                logger.debug(f"跳过保存商品信息：商品详情为空 - {item_id}")
                return False

            with self.lock:
                cursor = self.conn.cursor()

                # 检查商品是否已存在
                cursor.execute('''
                SELECT id, item_detail FROM item_info
                WHERE cookie_id = ? AND item_id = ?
                ''', (cookie_id, item_id))

                existing = cursor.fetchone()

                if existing:
                    # 如果传入的商品详情有值，则用最新数据覆盖
                    if item_data is not None and item_data:
                        # 处理字符串类型的详情数据
                        if isinstance(item_data, str):
                            cursor.execute('''
                            UPDATE item_info SET
                                item_detail = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE cookie_id = ? AND item_id = ?
                            ''', (item_data, cookie_id, item_id))
                        else:
                            # 处理字典类型的详情数据（向后兼容）
                            cursor.execute('''
                            UPDATE item_info SET
                                item_title = ?, item_description = ?, item_category = ?,
                                item_price = ?, item_detail = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE cookie_id = ? AND item_id = ?
                            ''', (
                                item_data.get('title', ''),
                                item_data.get('description', ''),
                                item_data.get('category', ''),
                                item_data.get('price', ''),
                                json.dumps(item_data, ensure_ascii=False),
                                cookie_id, item_id
                            ))
                        logger.info(f"更新商品信息（覆盖）: {item_id}")
                    else:
                        # 如果商品详情没有数据，则不更新，只记录存在
                        logger.debug(f"商品信息已存在，无新数据，跳过更新: {item_id}")
                        return True
                else:
                    # 新增商品信息
                    if isinstance(item_data, str):
                        # 直接保存字符串详情
                        cursor.execute('''
                        INSERT INTO item_info (cookie_id, item_id, item_detail)
                        VALUES (?, ?, ?)
                        ''', (cookie_id, item_id, item_data))
                    else:
                        # 处理字典类型的详情数据（向后兼容）
                        cursor.execute('''
                        INSERT INTO item_info (cookie_id, item_id, item_title, item_description,
                                             item_category, item_price, item_detail)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            cookie_id, item_id,
                            item_data.get('title', '') if item_data else '',
                            item_data.get('description', '') if item_data else '',
                            item_data.get('category', '') if item_data else '',
                            item_data.get('price', '') if item_data else '',
                            json.dumps(item_data, ensure_ascii=False) if item_data else ''
                        ))
                    logger.info(f"新增商品信息: {item_id}")

                self.conn.commit()
                return True

        except Exception as e:
            logger.error(f"保存商品信息失败: {e}")
            self.conn.rollback()
            return False

    def get_item_info(self, cookie_id: str, item_id: str) -> Optional[Dict]:
        """获取商品信息

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID

        Returns:
            Dict: 商品信息，如果不存在返回None
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT * FROM item_info
                WHERE cookie_id = ? AND item_id = ?
                ''', (cookie_id, item_id))

                row = cursor.fetchone()
                if row:
                    columns = [description[0] for description in cursor.description]
                    item_info = dict(zip(columns, row))

                    # 解析item_detail JSON
                    if item_info.get('item_detail'):
                        try:
                            item_info['item_detail_parsed'] = json.loads(item_info['item_detail'])
                        except:
                            item_info['item_detail_parsed'] = {}
                    logger.info(f"item_info: {item_info}")
                    return item_info
                return None

        except Exception as e:
            logger.error(f"获取商品信息失败: {e}")
            return None

    def update_item_multi_spec_status(self, cookie_id: str, item_id: str, is_multi_spec: bool) -> bool:
        """更新商品的多规格状态"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                UPDATE item_info
                SET is_multi_spec = ?, updated_at = CURRENT_TIMESTAMP
                WHERE cookie_id = ? AND item_id = ?
                ''', (is_multi_spec, cookie_id, item_id))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"更新商品多规格状态成功: {item_id} -> {is_multi_spec}")
                    return True
                else:
                    logger.warning(f"商品不存在，无法更新多规格状态: {item_id}")
                    return False

        except Exception as e:
            logger.error(f"更新商品多规格状态失败: {e}")
            self.conn.rollback()
            return False

    def get_item_multi_spec_status(self, cookie_id: str, item_id: str) -> bool:
        """获取商品的多规格状态"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT is_multi_spec FROM item_info
                WHERE cookie_id = ? AND item_id = ?
                ''', (cookie_id, item_id))

                row = cursor.fetchone()
                if row:
                    return bool(row[0]) if row[0] is not None else False
                return False

        except Exception as e:
            logger.error(f"获取商品多规格状态失败: {e}")
            return False

    def update_item_multi_quantity_delivery_status(self, cookie_id: str, item_id: str, multi_quantity_delivery: bool) -> bool:
        """更新商品的多数量发货状态"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                UPDATE item_info
                SET multi_quantity_delivery = ?, updated_at = CURRENT_TIMESTAMP
                WHERE cookie_id = ? AND item_id = ?
                ''', (multi_quantity_delivery, cookie_id, item_id))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"更新商品多数量发货状态成功: {item_id} -> {multi_quantity_delivery}")
                    return True
                else:
                    logger.warning(f"未找到要更新的商品: {item_id}")
                    return False

        except Exception as e:
            logger.error(f"更新商品多数量发货状态失败: {e}")
            self.conn.rollback()
            return False

    def get_item_multi_quantity_delivery_status(self, cookie_id: str, item_id: str) -> bool:
        """获取商品的多数量发货状态"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT multi_quantity_delivery FROM item_info
                WHERE cookie_id = ? AND item_id = ?
                ''', (cookie_id, item_id))

                row = cursor.fetchone()
                if row:
                    return bool(row[0]) if row[0] is not None else False
                return False

        except Exception as e:
            logger.error(f"获取商品多数量发货状态失败: {e}")
            return False

    def get_items_by_cookie(self, cookie_id: str) -> List[Dict]:
        """获取指定Cookie的所有商品信息

        Args:
            cookie_id: Cookie ID

        Returns:
            List[Dict]: 商品信息列表
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT * FROM item_info
                WHERE cookie_id = ?
                ORDER BY updated_at DESC
                ''', (cookie_id,))

                columns = [description[0] for description in cursor.description]
                items = []

                for row in cursor.fetchall():
                    item_info = dict(zip(columns, row))

                    # 解析item_detail JSON
                    if item_info.get('item_detail'):
                        try:
                            item_info['item_detail_parsed'] = json.loads(item_info['item_detail'])
                        except:
                            item_info['item_detail_parsed'] = {}

                    items.append(item_info)

                return items

        except Exception as e:
            logger.error(f"获取Cookie商品信息失败: {e}")
            return []

    def get_all_items(self) -> List[Dict]:
        """获取所有商品信息

        Returns:
            List[Dict]: 所有商品信息列表
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT * FROM item_info
                ORDER BY updated_at DESC
                ''')

                columns = [description[0] for description in cursor.description]
                items = []

                for row in cursor.fetchall():
                    item_info = dict(zip(columns, row))

                    # 解析item_detail JSON
                    if item_info.get('item_detail'):
                        try:
                            item_info['item_detail_parsed'] = json.loads(item_info['item_detail'])
                        except:
                            item_info['item_detail_parsed'] = {}

                    items.append(item_info)

                return items

        except Exception as e:
            logger.error(f"获取所有商品信息失败: {e}")
            return []

    def update_item_detail(self, cookie_id: str, item_id: str, item_detail: str) -> bool:
        """更新商品详情（不覆盖商品标题等基本信息）

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID
            item_detail: 商品详情JSON字符串

        Returns:
            bool: 操作是否成功
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                # 只更新item_detail字段，不影响其他字段
                cursor.execute('''
                UPDATE item_info SET
                    item_detail = ?, updated_at = CURRENT_TIMESTAMP
                WHERE cookie_id = ? AND item_id = ?
                ''', (item_detail, cookie_id, item_id))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"更新商品详情成功: {item_id}")
                    return True
                else:
                    logger.warning(f"未找到要更新的商品: {item_id}")
                    return False

        except Exception as e:
            logger.error(f"更新商品详情失败: {e}")
            self.conn.rollback()
            return False

    def update_item_title_only(self, cookie_id: str, item_id: str, item_title: str) -> bool:
        """仅更新商品标题（并发安全）

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID
            item_title: 商品标题

        Returns:
            bool: 操作是否成功
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                # 使用 INSERT OR REPLACE 确保记录存在，但只更新标题字段
                cursor.execute('''
                INSERT INTO item_info (cookie_id, item_id, item_title, item_description,
                                     item_category, item_price, item_detail, created_at, updated_at)
                VALUES (?, ?, ?,
                       COALESCE((SELECT item_description FROM item_info WHERE cookie_id = ? AND item_id = ?), ''),
                       COALESCE((SELECT item_category FROM item_info WHERE cookie_id = ? AND item_id = ?), ''),
                       COALESCE((SELECT item_price FROM item_info WHERE cookie_id = ? AND item_id = ?), ''),
                       COALESCE((SELECT item_detail FROM item_info WHERE cookie_id = ? AND item_id = ?), ''),
                       COALESCE((SELECT created_at FROM item_info WHERE cookie_id = ? AND item_id = ?), CURRENT_TIMESTAMP),
                       CURRENT_TIMESTAMP)
                ON CONFLICT(cookie_id, item_id) DO UPDATE SET
                    item_title = excluded.item_title,
                    updated_at = CURRENT_TIMESTAMP
                ''', (cookie_id, item_id, item_title,
                      cookie_id, item_id, cookie_id, item_id, cookie_id, item_id,
                      cookie_id, item_id, cookie_id, item_id))

                self.conn.commit()
                logger.info(f"更新商品标题成功: {item_id} - {item_title}")
                return True

        except Exception as e:
            logger.error(f"更新商品标题失败: {e}")
            self.conn.rollback()
            return False

    def batch_save_item_basic_info(self, items_data: list) -> int:
        """批量保存商品基本信息（并发安全）

        Args:
            items_data: 商品数据列表，每个元素包含 cookie_id, item_id, item_title 等字段

        Returns:
            int: 成功保存的商品数量
        """
        if not items_data:
            return 0

        success_count = 0
        try:
            with self.lock:
                cursor = self.conn.cursor()

                # 使用事务批量处理
                cursor.execute('BEGIN TRANSACTION')

                for item_data in items_data:
                    try:
                        cookie_id = item_data.get('cookie_id')
                        item_id = item_data.get('item_id')
                        item_title = item_data.get('item_title', '')
                        item_description = item_data.get('item_description', '')
                        item_category = item_data.get('item_category', '')
                        item_price = item_data.get('item_price', '')
                        item_detail = item_data.get('item_detail', '')

                        if not cookie_id or not item_id:
                            continue

                        # 验证：如果没有商品标题，则跳过保存
                        if not item_title or not item_title.strip():
                            logger.debug(f"跳过批量保存商品信息：缺少商品标题 - {item_id}")
                            continue

                        # 使用 INSERT OR IGNORE + UPDATE 模式
                        cursor.execute('''
                        INSERT OR IGNORE INTO item_info (cookie_id, item_id, item_title, item_description,
                                                       item_category, item_price, item_detail, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ''', (cookie_id, item_id, item_title, item_description,
                              item_category, item_price, item_detail))

                        if cursor.rowcount == 0:
                            # 记录已存在，进行条件更新
                            update_sql = '''
                            UPDATE item_info SET
                                item_title = CASE WHEN (item_title IS NULL OR item_title = '') AND ? != '' THEN ? ELSE item_title END,
                                item_description = CASE WHEN (item_description IS NULL OR item_description = '') AND ? != '' THEN ? ELSE item_description END,
                                item_category = CASE WHEN (item_category IS NULL OR item_category = '') AND ? != '' THEN ? ELSE item_category END,
                                item_price = CASE WHEN (item_price IS NULL OR item_price = '') AND ? != '' THEN ? ELSE item_price END,
                                item_detail = CASE WHEN (item_detail IS NULL OR item_detail = '' OR TRIM(item_detail) = '') AND ? != '' THEN ? ELSE item_detail END,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE cookie_id = ? AND item_id = ?
                            '''
                            self._execute_sql(cursor, update_sql, (
                                item_title, item_title,
                                item_description, item_description,
                                item_category, item_category,
                                item_price, item_price,
                                item_detail, item_detail,
                                cookie_id, item_id
                            ))

                        success_count += 1

                    except Exception as item_e:
                        logger.warning(f"批量保存单个商品失败 {item_data.get('item_id', 'unknown')}: {item_e}")
                        continue

                cursor.execute('COMMIT')
                logger.info(f"批量保存商品信息完成: {success_count}/{len(items_data)} 个商品")
                return success_count

        except Exception as e:
            logger.error(f"批量保存商品信息失败: {e}")
            try:
                cursor.execute('ROLLBACK')
            except:
                pass
            return success_count

    def batch_update_item_title_price(self, items_data: list) -> int:
        """批量更新商品标题和价格（不更新商品详情）
        
        Args:
            items_data: 商品数据列表，每个元素包含 cookie_id, item_id, item_title, item_price
        
        Returns:
            int: 成功更新的商品数量
        """
        if not items_data:
            return 0
        
        success_count = 0
        try:
            with self.lock:
                cursor = self.conn.cursor()
                
                # 使用事务批量处理
                cursor.execute('BEGIN TRANSACTION')
                
                for item_data in items_data:
                    try:
                        cookie_id = item_data.get('cookie_id')
                        item_id = item_data.get('item_id')
                        item_title = item_data.get('item_title', '')
                        item_price = item_data.get('item_price', '')
                        item_category = item_data.get('item_category', '')
                        
                        if not cookie_id or not item_id:
                            continue
                        
                        # 只更新标题、价格和分类，不更新商品详情
                        update_sql = '''
                        UPDATE item_info SET
                            item_title = ?,
                            item_price = ?,
                            item_category = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE cookie_id = ? AND item_id = ?
                        '''
                        cursor.execute(update_sql, (
                            item_title,
                            item_price,
                            item_category,
                            cookie_id,
                            item_id
                        ))
                        
                        if cursor.rowcount > 0:
                            success_count += 1
                    
                    except Exception as item_e:
                        logger.warning(f"批量更新单个商品失败 {item_data.get('item_id', 'unknown')}: {item_e}")
                        continue
                
                cursor.execute('COMMIT')
                logger.info(f"批量更新商品标题和价格完成: {success_count}/{len(items_data)} 个商品")
                return success_count
        
        except Exception as e:
            logger.error(f"批量更新商品标题和价格失败: {e}")
            try:
                cursor.execute('ROLLBACK')
            except:
                pass
            return success_count

    def delete_item_info(self, cookie_id: str, item_id: str) -> bool:
        """删除商品信息

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID

        Returns:
            bool: 操作是否成功
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM item_info WHERE cookie_id = ? AND item_id = ?',
                             (cookie_id, item_id))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"删除商品信息成功: {cookie_id} - {item_id}")
                    return True
                else:
                    logger.warning(f"未找到要删除的商品信息: {cookie_id} - {item_id}")
                    return False

        except Exception as e:
            logger.error(f"删除商品信息失败: {e}")
            self.conn.rollback()
            return False

    def batch_delete_item_info(self, items_to_delete: list) -> int:
        """批量删除商品信息

        Args:
            items_to_delete: 要删除的商品列表，每个元素包含 cookie_id 和 item_id

        Returns:
            int: 成功删除的商品数量
        """
        if not items_to_delete:
            return 0

        success_count = 0
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('BEGIN TRANSACTION')

                for item_data in items_to_delete:
                    try:
                        cookie_id = item_data.get('cookie_id')
                        item_id = item_data.get('item_id')

                        if not cookie_id or not item_id:
                            continue

                        cursor.execute('DELETE FROM item_info WHERE cookie_id = ? AND item_id = ?',
                                     (cookie_id, item_id))

                        if cursor.rowcount > 0:
                            success_count += 1
                            logger.debug(f"删除商品信息: {cookie_id} - {item_id}")

                    except Exception as item_e:
                        logger.warning(f"删除单个商品失败 {item_data.get('item_id', 'unknown')}: {item_e}")
                        continue

                cursor.execute('COMMIT')
                logger.info(f"批量删除商品信息完成: {success_count}/{len(items_to_delete)} 个商品")
                return success_count

        except Exception as e:
            logger.error(f"批量删除商品信息失败: {e}")
            try:
                cursor.execute('ROLLBACK')
            except:
                pass
            return success_count

    # ==================== 用户设置管理方法 ====================

    def get_user_settings(self, user_id: int):
        """获取用户的所有设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT key, value, description, updated_at
                FROM user_settings
                WHERE user_id = ?
                ORDER BY key
                ''', (user_id,))

                settings = {}
                for row in cursor.fetchall():
                    settings[row[0]] = {
                        'value': row[1],
                        'description': row[2],
                        'updated_at': row[3]
                    }

                return settings
            except Exception as e:
                logger.error(f"获取用户设置失败: {e}")
                return {}

    def get_user_setting(self, user_id: int, key: str):
        """获取用户的特定设置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT value, description, updated_at
                FROM user_settings
                WHERE user_id = ? AND key = ?
                ''', (user_id, key))

                row = cursor.fetchone()
                if row:
                    return {
                        'key': key,
                        'value': row[0],
                        'description': row[1],
                        'updated_at': row[2]
                    }
                return None
            except Exception as e:
                logger.error(f"获取用户设置失败: {e}")
                return None

    def set_user_setting(self, user_id: int, key: str, value: str, description: str = None):
        """设置用户配置"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                INSERT OR REPLACE INTO user_settings (user_id, key, value, description, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (user_id, key, value, description))

                self.conn.commit()
                logger.info(f"用户设置更新成功: user_id={user_id}, key={key}")
                return True
            except Exception as e:
                logger.error(f"设置用户配置失败: {e}")
                self.conn.rollback()
                return False

    # ==================== 管理员专用方法 ====================

    def get_all_users(self):
        """获取所有用户信息（管理员专用）"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 检查is_admin列是否存在
                cursor.execute("PRAGMA table_info(users)")
                columns = [col[1] for col in cursor.fetchall()]
                has_is_admin = 'is_admin' in columns

                if has_is_admin:
                    cursor.execute('''
                    SELECT id, username, email, created_at, updated_at, is_admin
                    FROM users
                    ORDER BY created_at DESC
                    ''')
                else:
                    cursor.execute('''
                    SELECT id, username, email, created_at, updated_at
                    FROM users
                    ORDER BY created_at DESC
                    ''')

                users = []
                for row in cursor.fetchall():
                    user_data = {
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'created_at': row[3],
                        'updated_at': row[4],
                    }
                    # 设置is_admin: 如果有该列则使用，否则admin用户名默认为管理员
                    if has_is_admin:
                        user_data['is_admin'] = bool(row[5]) if row[5] is not None else (row[1] == 'admin')
                    else:
                        user_data['is_admin'] = (row[1] == 'admin')
                    users.append(user_data)

                return users
            except Exception as e:
                logger.error(f"获取所有用户失败: {e}")
                return []

    def get_user_by_id(self, user_id: int):
        """根据ID获取用户信息"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                # 检查is_admin列是否存在
                cursor.execute("PRAGMA table_info(users)")
                columns = [col[1] for col in cursor.fetchall()]
                has_is_admin = 'is_admin' in columns

                if has_is_admin:
                    cursor.execute('''
                    SELECT id, username, email, created_at, updated_at, is_admin
                    FROM users
                    WHERE id = ?
                    ''', (user_id,))
                else:
                    cursor.execute('''
                    SELECT id, username, email, created_at, updated_at
                    FROM users
                    WHERE id = ?
                    ''', (user_id,))

                row = cursor.fetchone()
                if row:
                    user_data = {
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'created_at': row[3],
                        'updated_at': row[4],
                    }
                    if has_is_admin:
                        user_data['is_admin'] = bool(row[5]) if row[5] is not None else (row[1] == 'admin')
                    else:
                        user_data['is_admin'] = (row[1] == 'admin')
                    return user_data
                return None
            except Exception as e:
                logger.error(f"获取用户信息失败: {e}")
                return None

    def update_user_admin_status(self, user_id: int, is_admin: bool) -> bool:
        """更新用户管理员状态"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                ''', (1 if is_admin else 0, user_id))

                self.conn.commit()
                logger.info(f"用户管理员状态更新成功: user_id={user_id}, is_admin={is_admin}")
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"更新用户管理员状态失败: {e}")
                self.conn.rollback()
                return False

    def delete_user_and_data(self, user_id: int):
        """删除用户及其所有相关数据"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 开始事务
                cursor.execute('BEGIN TRANSACTION')

                # 删除用户相关的所有数据
                # 1. 删除用户设置
                cursor.execute('DELETE FROM user_settings WHERE user_id = ?', (user_id,))

                # 2. 删除用户的卡券
                cursor.execute('DELETE FROM cards WHERE user_id = ?', (user_id,))

                # 3. 删除用户的发货规则
                cursor.execute('DELETE FROM delivery_rules WHERE user_id = ?', (user_id,))

                # 4. 删除用户的通知渠道
                cursor.execute('DELETE FROM notification_channels WHERE user_id = ?', (user_id,))

                # 5. 删除用户的Cookie
                cursor.execute('DELETE FROM cookies WHERE user_id = ?', (user_id,))

                # 6. 删除用户的关键字
                cursor.execute('DELETE FROM keywords WHERE cookie_id IN (SELECT id FROM cookies WHERE user_id = ?)', (user_id,))

                # 7. 删除用户的默认回复
                cursor.execute('DELETE FROM default_replies WHERE cookie_id IN (SELECT id FROM cookies WHERE user_id = ?)', (user_id,))

                # 8. 删除用户的AI回复设置
                cursor.execute('DELETE FROM ai_reply_settings WHERE cookie_id IN (SELECT id FROM cookies WHERE user_id = ?)', (user_id,))

                # 9. 删除用户的消息通知
                cursor.execute('DELETE FROM message_notifications WHERE cookie_id IN (SELECT id FROM cookies WHERE user_id = ?)', (user_id,))

                # 10. 最后删除用户本身
                cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

                # 提交事务
                cursor.execute('COMMIT')

                logger.info(f"用户及相关数据删除成功: user_id={user_id}")
                return True

            except Exception as e:
                # 回滚事务
                cursor.execute('ROLLBACK')
                logger.error(f"删除用户及相关数据失败: {e}")
                return False

    def get_table_data(self, table_name: str):
        """获取指定表的所有数据"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 获取表结构
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns_info = cursor.fetchall()
                columns = [col[1] for col in columns_info]  # 列名

                # 获取表数据
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()

                # 转换为字典列表
                data = []
                for row in rows:
                    row_dict = {}
                    for i, value in enumerate(row):
                        row_dict[columns[i]] = value
                    data.append(row_dict)

                return data, columns

            except Exception as e:
                logger.error(f"获取表数据失败: {table_name} - {e}")
                return [], []

    def insert_or_update_order(self, order_id: str, item_id: str = None, buyer_id: str = None,
                              spec_name: str = None, spec_value: str = None, quantity: str = None,
                              amount: str = None, order_status: str = None, cookie_id: str = None,
                              sid: str = None, spec_name_2: str = None, spec_value_2: str = None,
                              buyer_nick: str = None):
        """插入或更新订单信息

        Args:
            order_id: 订单ID
            item_id: 商品ID
            buyer_id: 买家ID
            buyer_nick: 买家昵称
            spec_name: 规格名称
            spec_value: 规格值
            spec_name_2: 规格2名称
            spec_value_2: 规格2值
            quantity: 数量
            amount: 金额
            order_status: 订单状态
            cookie_id: Cookie ID
            sid: 会话ID（如 56226853668@goofish 或 56226853668），用于简化消息匹配订单
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 检查cookie_id是否在cookies表中存在（如果提供了cookie_id）
                if cookie_id:
                    cursor.execute("SELECT id FROM cookies WHERE id = ?", (cookie_id,))
                    cookie_exists = cursor.fetchone()
                    if not cookie_exists:
                        logger.warning(f"Cookie ID {cookie_id} 不存在于cookies表中，拒绝插入订单 {order_id}")
                        return False

                # 检查订单是否已存在
                cursor.execute("SELECT order_id FROM orders WHERE order_id = ?", (order_id,))
                existing = cursor.fetchone()

                if existing:
                    # 更新现有订单
                    update_fields = []
                    update_values = []

                    if item_id is not None:
                        update_fields.append("item_id = ?")
                        update_values.append(item_id)
                    if buyer_id is not None:
                        update_fields.append("buyer_id = ?")
                        update_values.append(buyer_id)
                    if buyer_nick is not None:
                        update_fields.append("buyer_nick = ?")
                        update_values.append(buyer_nick)
                    if sid is not None:
                        update_fields.append("sid = ?")
                        update_values.append(sid)
                    if spec_name is not None:
                        update_fields.append("spec_name = ?")
                        update_values.append(spec_name)
                    if spec_value is not None:
                        update_fields.append("spec_value = ?")
                        update_values.append(spec_value)
                    if spec_name_2 is not None:
                        update_fields.append("spec_name_2 = ?")
                        update_values.append(spec_name_2)
                    if spec_value_2 is not None:
                        update_fields.append("spec_value_2 = ?")
                        update_values.append(spec_value_2)
                    if quantity is not None:
                        update_fields.append("quantity = ?")
                        update_values.append(quantity)
                    if amount is not None:
                        update_fields.append("amount = ?")
                        update_values.append(amount)
                    if order_status is not None:
                        update_fields.append("order_status = ?")
                        update_values.append(order_status)
                    if cookie_id is not None:
                        update_fields.append("cookie_id = ?")
                        update_values.append(cookie_id)

                    if update_fields:
                        update_fields.append("updated_at = CURRENT_TIMESTAMP")
                        update_values.append(order_id)

                        sql = f"UPDATE orders SET {', '.join(update_fields)} WHERE order_id = ?"
                        cursor.execute(sql, update_values)
                        logger.info(f"更新订单信息: {order_id}")
                else:
                    # 插入新订单
                    cursor.execute('''
                    INSERT INTO orders (order_id, item_id, buyer_id, buyer_nick, sid, spec_name, spec_value,
                                      spec_name_2, spec_value_2, quantity, amount, order_status, cookie_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (order_id, item_id, buyer_id, buyer_nick, sid, spec_name, spec_value,
                          spec_name_2, spec_value_2, quantity, amount, order_status or 'unknown', cookie_id))
                    logger.info(f"插入新订单: {order_id}")

                self.conn.commit()
                return True

            except Exception as e:
                logger.error(f"插入或更新订单失败: {order_id} - {e}")
                self.conn.rollback()
                return False

    def get_order_by_id(self, order_id: str):
        """根据订单ID获取订单信息"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT order_id, item_id, buyer_id, buyer_nick, sid, spec_name, spec_value,
                       spec_name_2, spec_value_2, quantity, amount, order_status, cookie_id, created_at, updated_at
                FROM orders WHERE order_id = ?
                ''', (order_id,))

                row = cursor.fetchone()
                if row:
                    return {
                        'order_id': row[0],
                        'item_id': row[1],
                        'buyer_id': row[2],
                        'buyer_nick': row[3],
                        'sid': row[4],
                        'spec_name': row[5],
                        'spec_value': row[6],
                        'spec_name_2': row[7],
                        'spec_value_2': row[8],
                        'quantity': row[9],
                        'amount': row[10],
                        'order_status': row[11],
                        'cookie_id': row[12],
                        'created_at': row[13],
                        'updated_at': row[14]
                    }
                return None

            except Exception as e:
                logger.error(f"获取订单信息失败: {order_id} - {e}")
                return None

    def get_orders_by_cookie(self, cookie_id: str, limit: int = 100):
        """根据Cookie ID获取订单列表"""
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT order_id, item_id, buyer_id, buyer_nick, sid, spec_name, spec_value,
                       spec_name_2, spec_value_2, quantity, amount, order_status, created_at, updated_at
                FROM orders WHERE cookie_id = ?
                ORDER BY created_at DESC LIMIT ?
                ''', (cookie_id, limit))

                orders = []
                for row in cursor.fetchall():
                    orders.append({
                        'order_id': row[0],
                        'item_id': row[1],
                        'buyer_id': row[2],
                        'buyer_nick': row[3],
                        'sid': row[4],
                        'spec_name': row[5],
                        'spec_value': row[6],
                        'spec_name_2': row[7],
                        'spec_value_2': row[8],
                        'quantity': row[9],
                        'amount': row[10],
                        'order_status': row[11],
                        'created_at': row[12],
                        'updated_at': row[13]
                    })

                return orders

            except Exception as e:
                logger.error(f"获取Cookie订单列表失败: {cookie_id} - {e}")
                return []

    def update_buyer_nick_by_buyer_id(self, buyer_id: str, buyer_nick: str, cookie_id: str = None):
        """根据买家ID更新所有相关订单的买家昵称

        当收到买家消息时调用此方法，自动更新该买家所有订单的昵称
        允许覆盖已有昵称，以便使用更准确的昵称替换可能不准确的值

        Args:
            buyer_id: 买家用户ID
            buyer_nick: 买家昵称
            cookie_id: Cookie ID（可选，用于限定账号）

        Returns:
            int: 更新的订单数量
        """
        if not buyer_id or not buyer_nick:
            return 0

        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 更新该买家所有订单的昵称（允许覆盖已有值）
                if cookie_id:
                    cursor.execute('''
                    UPDATE orders SET buyer_nick = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE buyer_id = ? AND cookie_id = ?
                    ''', (buyer_nick, buyer_id, cookie_id))
                else:
                    cursor.execute('''
                    UPDATE orders SET buyer_nick = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE buyer_id = ?
                    ''', (buyer_nick, buyer_id))

                updated_count = cursor.rowcount
                self.conn.commit()

                if updated_count > 0:
                    logger.info(f"已更新买家 {buyer_id} 的 {updated_count} 个订单昵称为: {buyer_nick}")

                return updated_count

            except Exception as e:
                logger.error(f"更新买家昵称失败: buyer_id={buyer_id} - {e}")
                self.conn.rollback()
                return 0

    def get_recent_order_by_buyer_id(self, buyer_id: str, cookie_id: str = None, status: str = None, minutes: int = 10):
        """根据买家ID获取最近的订单信息
        
        Args:
            buyer_id: 买家用户ID
            cookie_id: Cookie ID（可选，用于限定账号）
            status: 订单状态过滤（可选，如'processing'）
            minutes: 查询最近多少分钟内的订单，默认10分钟
        
        Returns:
            Dict: 订单信息，包含order_id, item_id等
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 构建查询条件
                conditions = ["buyer_id = ?"]
                params = [buyer_id]
                
                if cookie_id:
                    conditions.append("cookie_id = ?")
                    params.append(cookie_id)
                
                if status:
                    conditions.append("order_status = ?")
                    params.append(status)
                
                # 添加时间限制
                conditions.append("datetime(created_at) >= datetime('now', ?)")
                params.append(f'-{minutes} minutes')
                
                where_clause = " AND ".join(conditions)
                
                cursor.execute(f'''
                SELECT order_id, item_id, buyer_id, buyer_nick, sid, spec_name, spec_value,
                       spec_name_2, spec_value_2, quantity, amount, order_status, cookie_id, created_at, updated_at
                FROM orders
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT 1
                ''', params)

                row = cursor.fetchone()
                if row:
                    logger.info(f"根据买家ID找到最近订单: buyer_id={buyer_id}, order_id={row[0]}, item_id={row[1]}")
                    return {
                        'order_id': row[0],
                        'item_id': row[1],
                        'buyer_id': row[2],
                        'buyer_nick': row[3],
                        'sid': row[4],
                        'spec_name': row[5],
                        'spec_value': row[6],
                        'spec_name_2': row[7],
                        'spec_value_2': row[8],
                        'quantity': row[9],
                        'amount': row[10],
                        'order_status': row[11],
                        'cookie_id': row[12],
                        'created_at': row[13],
                        'updated_at': row[14]
                    }
                
                logger.warning(f"未找到买家 {buyer_id} 的最近订单 (cookie_id={cookie_id}, status={status}, minutes={minutes})")
                return None
                
            except Exception as e:
                logger.error(f"根据买家ID获取订单失败: buyer_id={buyer_id} - {e}")
                return None

    def get_recent_order_by_sid(self, sid: str, cookie_id: str = None, status: str = None, minutes: int = 10):
        """根据会话ID(sid)获取最近的订单信息
        
        用于简化消息场景：当ws消息只包含sid（如56226853668@goofish）而无法获取buyer_id时，
        通过sid查找对应的订单。
        
        Args:
            sid: 会话ID（如 56226853668@goofish 或 56226853668）
            cookie_id: Cookie ID（可选，用于限定账号）
            status: 订单状态过滤（可选，如'processing'）
            minutes: 查询最近多少分钟内的订单，默认10分钟
        
        Returns:
            Dict: 订单信息，包含order_id, item_id, sid等
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 处理sid格式：可能是 "56226853668@goofish" 或 "56226853668"
                # 数据库中存储的可能是完整格式或纯数字格式，需要同时匹配
                sid_clean = sid.split('@')[0] if '@' in sid else sid
                
                # 构建查询条件：同时匹配完整sid和纯数字sid
                conditions = ["(sid = ? OR sid = ? OR sid LIKE ?)"]
                params = [sid, sid_clean, f"{sid_clean}@%"]
                
                if cookie_id:
                    conditions.append("cookie_id = ?")
                    params.append(cookie_id)
                
                if status:
                    conditions.append("order_status != 'shipped' ")
                
                # 添加时间限制
                conditions.append("datetime(created_at) >= datetime('now', ?)")
                params.append(f'-{minutes} minutes')
                
                where_clause = " AND ".join(conditions)
                
                sql = f'''
                SELECT order_id, item_id, buyer_id, buyer_nick, sid, spec_name, spec_value,
                       spec_name_2, spec_value_2, quantity, amount, order_status, cookie_id, created_at, updated_at
                FROM orders
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT 1
                '''

                # 打印可直接执行的完整SQL语句，方便调试
                debug_sql = sql
                for param in params:
                    if param is None:
                        debug_sql = debug_sql.replace('?', 'NULL', 1)
                    elif isinstance(param, str):
                        debug_sql = debug_sql.replace('?', f"'{param}'", 1)
                    else:
                        debug_sql = debug_sql.replace('?', str(param), 1)
                logger.info(f"[get_recent_order_by_sid] 可执行SQL: {debug_sql.strip()}")

                cursor.execute(sql, params)

                row = cursor.fetchone()
                if row:
                    logger.info(f"根据sid找到最近订单: sid={sid}, order_id={row[0]}, item_id={row[1]}")
                    return {
                        'order_id': row[0],
                        'item_id': row[1],
                        'buyer_id': row[2],
                        'buyer_nick': row[3],
                        'sid': row[4],
                        'spec_name': row[5],
                        'spec_value': row[6],
                        'spec_name_2': row[7],
                        'spec_value_2': row[8],
                        'quantity': row[9],
                        'amount': row[10],
                        'order_status': row[11],
                        'cookie_id': row[12],
                        'created_at': row[13],
                        'updated_at': row[14]
                    }
                
                logger.warning(f"未找到sid {sid} 的最近订单 (cookie_id={cookie_id}, status={status}, minutes={minutes})")
                return None
                
            except Exception as e:
                logger.error(f"根据sid获取订单失败: sid={sid} - {e}")
                return None

    def update_order_yifan_status(self, order_id: str, yifan_orderno: str = None,
                                  delivery_status: str = None, callback_data: str = None):
        """
        更新订单的亦凡API状态
        
        Args:
            order_id: 订单ID（用户订单号）
            yifan_orderno: 亦凡平台订单号
            delivery_status: 发货状态（delivered/processing/failed等）
            callback_data: 回调原始数据（JSON字符串）
        
        Returns:
            bool: 是否更新成功
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 首先检查订单是否存在
                cursor.execute("SELECT order_id FROM orders WHERE order_id = ?", (order_id,))
                if not cursor.fetchone():
                    logger.warning(f"订单不存在: {order_id}")
                    return False
                
                # 检查是否存在yifan相关字段，如果不存在则添加
                try:
                    cursor.execute("SELECT yifan_orderno FROM orders LIMIT 1")
                except:
                    # 字段不存在，需要添加
                    logger.info("为orders表添加亦凡回调相关字段...")
                    cursor.execute("ALTER TABLE orders ADD COLUMN yifan_orderno TEXT")
                    cursor.execute("ALTER TABLE orders ADD COLUMN delivery_status TEXT")
                    cursor.execute("ALTER TABLE orders ADD COLUMN callback_data TEXT")
                    cursor.execute("ALTER TABLE orders ADD COLUMN chat_id TEXT")
                    self.conn.commit()
                    logger.info("亦凡回调字段添加完成")
                
                # 构建更新语句
                update_fields = []
                update_values = []
                
                if yifan_orderno is not None:
                    update_fields.append("yifan_orderno = ?")
                    update_values.append(yifan_orderno)
                
                if delivery_status is not None:
                    update_fields.append("delivery_status = ?")
                    update_values.append(delivery_status)
                    # 同时更新order_status字段
                    update_fields.append("order_status = ?")
                    update_values.append(delivery_status)
                
                if callback_data is not None:
                    update_fields.append("callback_data = ?")
                    update_values.append(callback_data)
                
                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                update_values.append(order_id)
                
                # 执行更新
                sql = f"UPDATE orders SET {', '.join(update_fields)} WHERE order_id = ?"
                cursor.execute(sql, update_values)
                
                self.conn.commit()
                logger.info(f"更新订单亦凡状态成功: {order_id} -> {delivery_status}")
                return True
                
            except Exception as e:
                logger.error(f"更新订单亦凡状态失败: {order_id} - {e}")
                self.conn.rollback()
                return False

    def get_order_info(self, order_id: str):
        """
        获取订单完整信息（包括亦凡回调相关信息）
        
        Args:
            order_id: 订单ID
        
        Returns:
            Dict: 订单信息
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 检查是否存在yifan相关字段
                has_yifan_fields = False
                try:
                    cursor.execute("SELECT yifan_orderno FROM orders LIMIT 1")
                    has_yifan_fields = True
                except:
                    pass
                
                if has_yifan_fields:
                    cursor.execute('''
                    SELECT order_id, item_id, buyer_id, spec_name, spec_value,
                           quantity, amount, order_status, cookie_id, created_at, updated_at,
                           yifan_orderno, delivery_status, callback_data, chat_id
                    FROM orders WHERE order_id = ?
                    ''', (order_id,))
                    
                    row = cursor.fetchone()
                    if row:
                        return {
                            'order_id': row[0],
                            'item_id': row[1],
                            'buyer_id': row[2],
                            'spec_name': row[3],
                            'spec_value': row[4],
                            'quantity': row[5],
                            'amount': row[6],
                            'order_status': row[7],
                            'cookie_id': row[8],
                            'created_at': row[9],
                            'updated_at': row[10],
                            'yifan_orderno': row[11],
                            'delivery_status': row[12],
                            'callback_data': row[13],
                            'chat_id': row[14]
                        }
                else:
                    # 使用旧的查询方式
                    cursor.execute('''
                    SELECT order_id, item_id, buyer_id, spec_name, spec_value,
                           quantity, amount, order_status, cookie_id, created_at, updated_at
                    FROM orders WHERE order_id = ?
                    ''', (order_id,))
                    
                    row = cursor.fetchone()
                    if row:
                        return {
                            'order_id': row[0],
                            'item_id': row[1],
                            'buyer_id': row[2],
                            'spec_name': row[3],
                            'spec_value': row[4],
                            'quantity': row[5],
                            'amount': row[6],
                            'order_status': row[7],
                            'cookie_id': row[8],
                            'created_at': row[9],
                            'updated_at': row[10]
                        }
                
                return None
                
            except Exception as e:
                logger.error(f"获取订单信息失败: {order_id} - {e}")
                return None

    def get_order_by_yifan_orderno(self, yifan_orderno: str):
        """
        根据亦凡订单号查找订单信息
        
        Args:
            yifan_orderno: 亦凡平台订单号
        
        Returns:
            Dict: 订单信息，如果未找到返回None
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 检查是否存在yifan相关字段
                try:
                    cursor.execute("SELECT yifan_orderno FROM orders LIMIT 1")
                except:
                    logger.warning("orders表不包含yifan_orderno字段")
                    return None
                
                cursor.execute('''
                SELECT order_id, item_id, buyer_id, spec_name, spec_value,
                       quantity, amount, order_status, cookie_id, created_at, updated_at,
                       yifan_orderno, delivery_status, callback_data, chat_id
                FROM orders WHERE yifan_orderno = ?
                ''', (yifan_orderno,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'order_id': row[0],
                        'item_id': row[1],
                        'buyer_id': row[2],
                        'spec_name': row[3],
                        'spec_value': row[4],
                        'quantity': row[5],
                        'amount': row[6],
                        'order_status': row[7],
                        'cookie_id': row[8],
                        'created_at': row[9],
                        'updated_at': row[10],
                        'yifan_orderno': row[11],
                        'delivery_status': row[12],
                        'callback_data': row[13],
                        'chat_id': row[14]
                    }
                
                return None
                
            except Exception as e:
                logger.error(f"根据亦凡订单号查找订单失败: {yifan_orderno} - {e}")
                return None

    def update_order_chat_id(self, order_id: str, chat_id: str):
        """
        更新订单的chat_id（用于后续回调通知）
        
        Args:
            order_id: 订单ID
            chat_id: 聊天ID
        
        Returns:
            bool: 是否更新成功
        """
        with self.lock:
            try:
                cursor = self.conn.cursor()
                
                # 检查是否存在chat_id字段，如果不存在则添加
                try:
                    cursor.execute("SELECT chat_id FROM orders LIMIT 1")
                except:
                    logger.info("为orders表添加chat_id字段...")
                    cursor.execute("ALTER TABLE orders ADD COLUMN chat_id TEXT")
                    self.conn.commit()
                
                cursor.execute("UPDATE orders SET chat_id = ? WHERE order_id = ?", (chat_id, order_id))
                self.conn.commit()
                return True
                
            except Exception as e:
                logger.error(f"更新订单chat_id失败: {order_id} - {e}")
                return False

    def delete_table_record(self, table_name: str, record_id: str):
        """删除指定表的指定记录"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 根据表名确定主键字段
                primary_key_map = {
                    'users': 'id',
                    'cookies': 'id',
                    'cookie_status': 'id',
                    'keywords': 'id',
                    'default_replies': 'id',
                    'default_reply_records': 'id',
                    'item_replay': 'item_id',
                    'ai_reply_settings': 'id',
                    'ai_conversations': 'id',
                    'ai_item_cache': 'id',
                    'item_info': 'id',
                    'message_notifications': 'id',
                    'cards': 'id',
                    'delivery_rules': 'id',
                    'notification_channels': 'id',
                    'user_settings': 'id',
                    'system_settings': 'id',
                    'email_verifications': 'id',
                    'captcha_codes': 'id',
                    'orders': 'order_id'
                }

                primary_key = primary_key_map.get(table_name, 'id')

                # 删除记录
                cursor.execute(f"DELETE FROM {table_name} WHERE {primary_key} = ?", (record_id,))

                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"删除表记录成功: {table_name}.{record_id}")
                    return True
                else:
                    logger.warning(f"删除表记录失败，记录不存在: {table_name}.{record_id}")
                    return False

            except Exception as e:
                logger.error(f"删除表记录失败: {table_name}.{record_id} - {e}")
                self.conn.rollback()
                return False

    def clear_table_data(self, table_name: str):
        """清空指定表的所有数据"""
        with self.lock:
            try:
                cursor = self.conn.cursor()

                # 清空表数据
                cursor.execute(f"DELETE FROM {table_name}")

                # 重置自增ID（如果有的话）
                cursor.execute(f"DELETE FROM sqlite_sequence WHERE name = ?", (table_name,))

                self.conn.commit()
                logger.info(f"清空表数据成功: {table_name}")
                return True

            except Exception as e:
                logger.error(f"清空表数据失败: {table_name} - {e}")
                self.conn.rollback()
                return False

    def upgrade_keywords_table_for_image_support(self, cursor):
        """升级keywords表以支持图片关键词"""
        try:
            logger.info("开始升级keywords表以支持图片关键词...")

            # 检查是否已经有type字段
            cursor.execute("PRAGMA table_info(keywords)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'type' not in columns:
                logger.info("添加type字段到keywords表...")
                cursor.execute("ALTER TABLE keywords ADD COLUMN type TEXT DEFAULT 'text'")

            if 'image_url' not in columns:
                logger.info("添加image_url字段到keywords表...")
                cursor.execute("ALTER TABLE keywords ADD COLUMN image_url TEXT")

            # 为现有记录设置默认类型
            cursor.execute("UPDATE keywords SET type = 'text' WHERE type IS NULL")

            logger.info("keywords表升级完成")
            return True

        except Exception as e:
            logger.error(f"升级keywords表失败: {e}")
            raise
    def get_item_replay(self, item_id: str) -> Optional[Dict[str, Any]]:
        """
        根据商品ID获取商品回复信息，并返回统一格式

        Args:
            item_id (str): 商品ID

        Returns:
            Optional[Dict[str, Any]]: 商品回复信息字典（统一格式），找不到返回 None
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    SELECT reply_content FROM item_replay
                    WHERE item_id = ?
                ''', (item_id,))

                row = cursor.fetchone()
                if row:
                    (reply_content,) = row
                    return {
                        'reply_content': reply_content or ''
                    }
                return None
        except Exception as e:
            logger.error(f"获取商品回复失败: {e}")
            return None

    def get_item_reply(self, cookie_id: str, item_id: str) -> Optional[Dict[str, Any]]:
        """
        获取指定账号和商品的回复内容

        Args:
            cookie_id (str): 账号ID
            item_id (str): 商品ID

        Returns:
            Dict: 包含回复内容的字典，如果不存在返回None
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    SELECT reply_content, created_at, updated_at
                    FROM item_replay
                    WHERE cookie_id = ? AND item_id = ?
                ''', (cookie_id, item_id))

                row = cursor.fetchone()
                if row:
                    return {
                        'reply_content': row[0] or '',
                        'created_at': row[1],
                        'updated_at': row[2]
                    }
                return None
        except Exception as e:
            logger.error(f"获取指定商品回复失败: {e}")
            return None

    def update_item_reply(self, cookie_id: str, item_id: str, reply_content: str) -> bool:
        """
        更新指定cookie和item的回复内容及更新时间

        Args:
            cookie_id (str): 账号ID
            item_id (str): 商品ID
            reply_content (str): 回复内容

        Returns:
            bool: 更新成功返回True，失败返回False
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    UPDATE item_replay
                    SET reply_content = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE cookie_id = ? AND item_id = ?
                ''', (reply_content, cookie_id, item_id))

                if cursor.rowcount == 0:
                    # 如果没更新到，说明该条记录不存在，可以考虑插入
                    cursor.execute('''
                        INSERT INTO item_replay (item_id, cookie_id, reply_content, created_at, updated_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ''', (item_id, cookie_id, reply_content))

                self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"更新商品回复失败: {e}")
            return False

    def get_itemReplays_by_cookie(self, cookie_id: str) -> List[Dict]:
        """获取指定Cookie的所有商品信息

        Args:
            cookie_id: Cookie ID

        Returns:
            List[Dict]: 商品信息列表
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                SELECT r.item_id, r.cookie_id, r.reply_content, r.created_at, r.updated_at, i.item_title, i.item_detail
                    FROM item_replay r
                    LEFT JOIN item_info i ON i.item_id = r.item_id
                    WHERE r.cookie_id = ?
                    ORDER BY r.updated_at DESC
                ''', (cookie_id,))

                columns = [description[0] for description in cursor.description]
                items = []

                for row in cursor.fetchall():
                    item_info = dict(zip(columns, row))

                    items.append(item_info)

                return items

        except Exception as e:
            logger.error(f"获取Cookie商品信息失败: {e}")
            return []

    def delete_item_reply(self, cookie_id: str, item_id: str) -> bool:
        """
        删除指定 cookie_id 和 item_id 的商品回复

        Args:
            cookie_id: Cookie ID
            item_id: 商品ID

        Returns:
            bool: 删除成功返回 True，失败返回 False
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    DELETE FROM item_replay
                    WHERE cookie_id = ? AND item_id = ?
                ''', (cookie_id, item_id))
                self.conn.commit()
                # 判断是否有删除行
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"删除商品回复失败: {e}")
            return False

    def batch_delete_item_replies(self, items: List[Dict[str, str]]) -> Dict[str, int]:
        """
        批量删除商品回复

        Args:
            items: List[Dict] 每个字典包含 cookie_id 和 item_id

        Returns:
            Dict[str, int]: 返回成功和失败的数量，例如 {"success_count": 3, "failed_count": 1}
        """
        success_count = 0
        failed_count = 0

        try:
            with self.lock:
                cursor = self.conn.cursor()
                for item in items:
                    cookie_id = item.get('cookie_id')
                    item_id = item.get('item_id')
                    if not cookie_id or not item_id:
                        failed_count += 1
                        continue
                    cursor.execute('''
                        DELETE FROM item_replay
                        WHERE cookie_id = ? AND item_id = ?
                    ''', (cookie_id, item_id))
                    if cursor.rowcount > 0:
                        success_count += 1
                    else:
                        failed_count += 1
                self.conn.commit()
        except Exception as e:
            logger.error(f"批量删除商品回复失败: {e}")
            # 整体失败则视为全部失败
            return {"success_count": 0, "failed_count": len(items)}

        return {"success_count": success_count, "failed_count": failed_count}

    # ==================== 风控日志管理 ====================

    def add_risk_control_log(self, cookie_id: str, event_type: str = 'slider_captcha',
                           event_description: str = None, processing_result: str = None,
                           processing_status: str = 'processing', error_message: str = None) -> bool:
        """
        添加风控日志记录

        Args:
            cookie_id: Cookie ID
            event_type: 事件类型，默认为'slider_captcha'
            event_description: 事件描述
            processing_result: 处理结果
            processing_status: 处理状态 ('processing', 'success', 'failed')
            error_message: 错误信息

        Returns:
            bool: 添加成功返回True，失败返回False
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO risk_control_logs
                    (cookie_id, event_type, event_description, processing_result, processing_status, error_message)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (cookie_id, event_type, event_description, processing_result, processing_status, error_message))
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"添加风控日志失败: {e}")
            return False

    def update_risk_control_log(self, log_id: int, processing_result: str = None,
                              processing_status: str = None, error_message: str = None) -> bool:
        """
        更新风控日志记录

        Args:
            log_id: 日志ID
            processing_result: 处理结果
            processing_status: 处理状态
            error_message: 错误信息

        Returns:
            bool: 更新成功返回True，失败返回False
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()

                # 构建更新语句
                update_fields = []
                params = []

                if processing_result is not None:
                    update_fields.append("processing_result = ?")
                    params.append(processing_result)

                if processing_status is not None:
                    update_fields.append("processing_status = ?")
                    params.append(processing_status)

                if error_message is not None:
                    update_fields.append("error_message = ?")
                    params.append(error_message)

                if update_fields:
                    update_fields.append("updated_at = CURRENT_TIMESTAMP")
                    params.append(log_id)

                    sql = f"UPDATE risk_control_logs SET {', '.join(update_fields)} WHERE id = ?"
                    cursor.execute(sql, params)
                    self.conn.commit()
                    return cursor.rowcount > 0

                return False
        except Exception as e:
            logger.error(f"更新风控日志失败: {e}")
            return False

    def get_risk_control_logs(self, cookie_id: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """
        获取风控日志列表

        Args:
            cookie_id: Cookie ID，为None时获取所有日志
            limit: 限制返回数量
            offset: 偏移量

        Returns:
            List[Dict]: 风控日志列表
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()

                if cookie_id:
                    cursor.execute('''
                        SELECT r.*, c.id as cookie_name
                        FROM risk_control_logs r
                        LEFT JOIN cookies c ON r.cookie_id = c.id
                        WHERE r.cookie_id = ?
                        ORDER BY r.created_at DESC
                        LIMIT ? OFFSET ?
                    ''', (cookie_id, limit, offset))
                else:
                    cursor.execute('''
                        SELECT r.*, c.id as cookie_name
                        FROM risk_control_logs r
                        LEFT JOIN cookies c ON r.cookie_id = c.id
                        ORDER BY r.created_at DESC
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))

                columns = [description[0] for description in cursor.description]
                logs = []

                for row in cursor.fetchall():
                    log_info = dict(zip(columns, row))
                    logs.append(log_info)

                return logs
        except Exception as e:
            logger.error(f"获取风控日志失败: {e}")
            return []

    def get_risk_control_logs_count(self, cookie_id: str = None) -> int:
        """
        获取风控日志总数

        Args:
            cookie_id: Cookie ID，为None时获取所有日志数量

        Returns:
            int: 日志总数
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()

                if cookie_id:
                    cursor.execute('SELECT COUNT(*) FROM risk_control_logs WHERE cookie_id = ?', (cookie_id,))
                else:
                    cursor.execute('SELECT COUNT(*) FROM risk_control_logs')

                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"获取风控日志数量失败: {e}")
            return 0

    def delete_risk_control_log(self, log_id: int) -> bool:
        """
        删除风控日志记录

        Args:
            log_id: 日志ID

        Returns:
            bool: 删除成功返回True，失败返回False
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('DELETE FROM risk_control_logs WHERE id = ?', (log_id,))
                self.conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"删除风控日志失败: {e}")
            return False
    
    def cleanup_old_data(self, days: int = 90) -> dict:
        """清理过期的历史数据，防止数据库无限增长
        
        Args:
            days: 保留最近N天的数据，默认90天
            
        Returns:
            清理统计信息
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                stats = {}
                
                # 清理AI对话历史（保留最近90天）
                try:
                    cursor.execute(
                        "DELETE FROM ai_conversations WHERE created_at < datetime('now', '-' || ? || ' days')",
                        (days,)
                    )
                    stats['ai_conversations'] = cursor.rowcount
                    if cursor.rowcount > 0:
                        logger.info(f"清理了 {cursor.rowcount} 条过期的AI对话记录（{days}天前）")
                except Exception as e:
                    logger.warning(f"清理AI对话历史失败: {e}")
                    stats['ai_conversations'] = 0
                
                # 清理风控日志（保留最近90天）
                try:
                    cursor.execute(
                        "DELETE FROM risk_control_logs WHERE created_at < datetime('now', '-' || ? || ' days')",
                        (days,)
                    )
                    stats['risk_control_logs'] = cursor.rowcount
                    if cursor.rowcount > 0:
                        logger.info(f"清理了 {cursor.rowcount} 条过期的风控日志（{days}天前）")
                except Exception as e:
                    logger.warning(f"清理风控日志失败: {e}")
                    stats['risk_control_logs'] = 0
                
                # 清理AI商品缓存（保留最近30天）
                cache_days = min(days, 30)  # AI商品缓存最多保留30天
                try:
                    cursor.execute(
                        "DELETE FROM ai_item_cache WHERE last_updated < datetime('now', '-' || ? || ' days')",
                        (cache_days,)
                    )
                    stats['ai_item_cache'] = cursor.rowcount
                    if cursor.rowcount > 0:
                        logger.info(f"清理了 {cursor.rowcount} 条过期的AI商品缓存（{cache_days}天前）")
                except Exception as e:
                    logger.warning(f"清理AI商品缓存失败: {e}")
                    stats['ai_item_cache'] = 0
                
                # 清理验证码记录（保留最近1天）
                try:
                    cursor.execute(
                        "DELETE FROM captcha_codes WHERE created_at < datetime('now', '-1 day')"
                    )
                    stats['captcha_codes'] = cursor.rowcount
                    if cursor.rowcount > 0:
                        logger.info(f"清理了 {cursor.rowcount} 条过期的验证码记录")
                except Exception as e:
                    logger.warning(f"清理验证码记录失败: {e}")
                    stats['captcha_codes'] = 0
                
                # 清理邮箱验证记录（保留最近7天）
                try:
                    cursor.execute(
                        "DELETE FROM email_verifications WHERE created_at < datetime('now', '-7 days')"
                    )
                    stats['email_verifications'] = cursor.rowcount
                    if cursor.rowcount > 0:
                        logger.info(f"清理了 {cursor.rowcount} 条过期的邮箱验证记录")
                except Exception as e:
                    logger.warning(f"清理邮箱验证记录失败: {e}")
                    stats['email_verifications'] = 0
                
                # 提交更改
                self.conn.commit()
                
                # 执行VACUUM以释放磁盘空间（仅当清理了大量数据时）
                total_cleaned = sum(stats.values())
                if total_cleaned > 100:
                    logger.info(f"共清理了 {total_cleaned} 条记录，执行VACUUM以释放磁盘空间...")
                    cursor.execute("VACUUM")
                    logger.info("VACUUM执行完成")
                    stats['vacuum_executed'] = True
                else:
                    stats['vacuum_executed'] = False
                
                stats['total_cleaned'] = total_cleaned
                return stats
                
        except Exception as e:
            logger.error(f"清理历史数据时出错: {e}")
            return {'error': str(e)}


# 全局单例
db_manager = DBManager()

# 确保进程结束时关闭数据库连接
import atexit
atexit.register(db_manager.close)
