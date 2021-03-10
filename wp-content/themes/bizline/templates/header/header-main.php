<?php
/**
 * Comtent for header
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress Theme
 */ ?>
<div class="bizline-bottom-header-wrapper">
	<div class="container">
		<section class="bizline-bottom-header">

			<div class="bizline-header-search">
				<button class="circular-focus screen-reader-text" data-goto=".bizline-header-search .bizline-toggle-search"><?php esc_html_e( 'Circular focus', 'bizline' ); ?></button>
				<?php get_search_form(); ?>
				<button type="button" class="close bizline-toggle-search">
					<i class="fa fa-times" aria-hidden="true"></i>
				</button>
				<button class="circular-focus screen-reader-text" data-goto=".bizline-header-search .search-field"><?php esc_html_e( 'Circular focus', 'bizline' ); ?></button>
			</div>		

			<div class="site-branding">
				<div>
					<?php the_custom_logo(); ?>
					<div>
						<?php if ( is_front_page() ) :
							?>
							<h1 class="site-title"><a href="<?php echo esc_url( home_url( '/' ) ); ?>" rel="home"><?php bloginfo( 'name' ); ?></a></h1>
							<?php
						else :
							?>
							<p class="site-title"><a href="<?php echo esc_url( home_url( '/' ) ); ?>" rel="home"><?php bloginfo( 'name' ); ?></a></p>
							<?php
						endif;
						$description = get_bloginfo( 'description', 'display' );
						if ( $description || is_customize_preview() ) :
							?>
							<p class="site-description"><?php echo $description; /* WPCS: xss ok. */ ?></p>
						<?php endif; ?>
					</div>
				</div>
			</div>

			<div class="bizline-navigation-n-options">

				<?php Bizline_Helper::get_menu( 'primary', true ); ?>
				
				<?php do_action( Bizline_Helper::fn_prefix( 'after_primary_menu' ) ); ?>
			</div>				
		 
		</section>

	</div>
</div>
<!-- nav bar section end -->