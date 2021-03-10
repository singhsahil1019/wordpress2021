<?php

$demo_templates_lists = array(

    'magazine-newspaper' => array(
        'title' => __( 'Magazine Newspaper', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => false,  /*Premium*/
        'type' => 'free',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),    /*Author Name*/
        'keywords' => array( 'Magazine Newspaper' ),  /*Search keyword*/
        'categories' => array( 'magazine-newspaper' ), /*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-free/magazine-newspaper-free-1/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-free/magazine-newspaper-free-1/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-free/magazine-newspaper-free-1/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-free/magazine-newspaper-free-1/magazine-newspaper-free-1.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/magazine-newspaper/',
        'plugins' => array()
    ),

    'magazine-newspaper-pro' => array(
        'title' => __( 'Magazine Newspaper Pro', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'type' => 'pro',
        'pro_url' => 'https://thebootstrapthemes.com/magazine-newspaper-pro/',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),    /*Author Name*/
        'keywords' => array( 'Magazine Newspaper' ),  /*Search keyword*/
        'categories' => array( 'magazine-newspaper' ), /*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-1/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-1/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-1/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-1/magazine-newspaper-pro-1.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/magazine-newspaper-pro/',
        'plugins' => array()
    ),

    'magazine-blog' => array(
        'title' => __( 'Magazine Blog', 'tbthemes-demo-import' ),/*Title*/
        'is_pro' => true,  /*Premium*/
        'type' => 'pro',
        'pro_url' => 'https://thebootstrapthemes.com/magazine-newspaper-pro/',
        'author' => __( 'thebootstrapthemes', 'tbthemes-demo-import' ),    /*Author Name*/
        'keywords' => array( 'Magazine Newspaper' ),  /*Search keyword*/
        'categories' => array( 'magazine-newspaper' ), /*Categories*/
        'template_url' => array(
            'content' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-2/content.json',
            'options' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-2/options.json',
            'widgets' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-2/widgets.json'
        ),
        'screenshot_url' => TBTHEMES_DEMO_IMPORT_TEMPLATE_URL.'magazine-newspaper-pro/magazine-newspaper-pro-2/magazine-newspaper-pro-2.jpg',
        'demo_url' => 'https://thebootstrapthemes.com/previews/magazine-blog/',
        'plugins' => array()
    ),

);