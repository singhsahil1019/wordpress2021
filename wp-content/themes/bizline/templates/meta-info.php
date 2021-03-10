<?php
/**
 * Displays the meta information
 *
 * @since 1.0.0
 *
 * @package Guternbiz WordPress Theme
 */?>

<?php if ( 'post' === get_post_type() || Bizline_Helper::is_static_front_page() ) : ?>
	<?php 
		$category = bizline_get( 'post-category' );
		$author   = bizline_get( 'post-author' );
		$date     = bizline_get( 'post-date' );
	if( $category || $author || $date ) : ?>
		<div class="entry-meta 
			<?php 
				if( is_single() ){
					echo esc_attr( 'single' );
				} 
			?>"
		>
			<?php 
			$author_id = get_query_var('author_id');
			Bizline_Helper::get_author_image( $author_id ); ?>
			<?php if( $author || $date ) : ?>
				<div class="author-info">
					<?php
						Bizline_Helper::the_date();			
						Bizline_Helper::posted_by( $author_id );
					?>
				</div>
			<?php endif; ?>
		</div>
		<?php Bizline_Helper::the_category(); ?>	
	<?php endif; ?>
<?php endif; ?>