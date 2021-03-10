<?php

$demo_templates_lists = array(

    'lifestyle-magazine' => array(
        'title' => __( 'Lifestyle Magazine', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => false,  /*Premium*/
        'type' => 'free',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),    /*Author Name*/
        'keywords' => array( 'Lifestyle Magazine, Lifestyle, Magazine'),  /*Search keyword*/
        'categories' => array( 'lifestyle-magazine' ), /*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-magazine/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-magazine/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-magazine-free-1/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-magazine/lifestyle-magazine-free-1.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-magazine/',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),

    'lifestyle-blog' =>array(
        'title' => __( 'Lifestyle Blog', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => false,  /*Premium*/
        'type' => 'free',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),/*Author Name*/
        'keywords' => array( 'Agility Conclave' ),/*Search keyword*/
        'categories' => array( 'lifestyle-magazine' ),/*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-blog/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-blog/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-blog/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-free/lifestyle-blog/lifestyle-magazine-free-2.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-blog/',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),


    'lifestyle-magazine-pro' => array(
        'title' => __( 'Lifestyle Magazine Pro', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'pro_url' => 'https://thebootstrapthemes.com/lifestyle-magazine-pro/', /*Pricing Url*/
        'type' => 'pro',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),/*Author Name*/
        'keywords' => array( 'Lifestyle Magazine Pro' ),/*Search keyword*/
        'categories' => array( 'lifestyle-magazine-pro' ),/*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-magazine-pro/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-magazine-pro/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-magazine-pro/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-magazine-pro/lifestyle-magazine-pro-1.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-magazine-pro/',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),


    'lifestyle-press-pro' =>array(
        'title' => __( 'Lifestyle Press Pro', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'pro_url' => 'https://thebootstrapthemes.com/lifestyle-magazine-pro/', /*Pricing Url*/
        'type' => 'pro',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),/*Author Name*/
        'keywords' => array( 'Lifestyle Magazine Pro' ),/*Search keyword*/
        'categories' => array( 'lifestyle-magazine-pro' ),/*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-press-pro/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-press-pro/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-press-pro/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-press-pro/lifestyle-magazine-pro-2.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-press',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),

    'lifestyle-fashion-pro' =>array(
        'title' => __( 'Lifestyle Fashion Pro', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'pro_url' => 'https://thebootstrapthemes.com/lifestyle-magazine-pro/', /*Pricing Url*/
        'type' => 'pro',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),/*Author Name*/
        'keywords' => array( 'Lifestyle Magazine Pro' ),/*Search keyword*/
        'categories' => array( 'lifestyle-magazine-pro' ),/*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-fashion-pro/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-fashion-pro/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-fashion-pro/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-fashion-pro/lifestyle-magazine-pro-3.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-fashion/',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),

    'lifestyle-diary-pro' =>array(
        'title' => __( 'Lifestyle Diary Pro', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'pro_url' => 'https://thebootstrapthemes.com/lifestyle-magazine-pro/', /*Pricing Url*/
        'type' => 'pro',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),/*Author Name*/
        'keywords' => array( 'Lifestyle Magazine Pro' ),/*Search keyword*/
        'categories' => array( 'lifestyle-magazine-pro' ),/*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-diary-pro/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-diary-pro/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-diary-pro/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-diary-pro/lifestyle-magazine-pro-4.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-diary/',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),

    'lifestyle-art-pro' =>array(
        'title' => __( 'Lifestyle Art Pro', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'pro_url' => 'https://thebootstrapthemes.com/lifestyle-magazine-pro/', /*Pricing Url*/
        'type' => 'pro',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),/*Author Name*/
        'keywords' => array( 'Lifestyle Magazine Pro' ),/*Search keyword*/
        'categories' => array( 'lifestyle-magazine-pro' ),/*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-art-pro/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-art-pro/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-art-pro/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'lifestyle-magazine-pro/lifestyle-art-pro/lifestyle-magazine-pro-5.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/lifestyle-art',
        'plugins' => array(
            array(
                'name'      => esc_html__( 'WooCommerce', 'tbthemes-demo-import' ),
                'slug'      => 'woocommerce',
            ),
            array(
                'name'      => esc_html__( 'BlossomThemes Instagram Feed', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-instagram-feed',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Toolkit', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-toolkit',
            ),

            array(
                'name'      => esc_html__( 'BlossomThemes Email Newsletter', 'tbthemes-demo-import' ),
                'slug'      => 'blossomthemes-email-newsletter',
            ),
        )
    ),
);